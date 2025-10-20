package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/compress"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
	jsoniter "github.com/json-iterator/go"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp"
)

var fastJSON = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	tokenCacheDuration  = 23 * time.Hour
	tokenCheckInterval  = 30 * time.Minute
	requestTimeout      = 15 * time.Second
	maxConnsPerHost     = 2000
	maxIdleConnDuration = 90 * time.Second
	maxResponseBodySize = 100 * 1024 * 1024
	redisPoolSize       = 50
	defaultLimit        = 25
	maxLimit            = 100
	defaultOffset       = 0
)

type Config struct {
	ClientID          string
	ClientIDHires     string
	ClientSecret      string
	ClientSecretHires string
	RefreshToken      string
	RefreshTokenHires string
	RedisURL          string
	RedisPort         string
	RedisPassword     string
	UserID            string
	Port              string
}

type TokenCache struct {
	Token     string
	ExpiresAt time.Time
	LastCheck time.Time
	mu        sync.RWMutex
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type PaginationParams struct {
	Limit  int
	Offset int
}

type PaginatedResponse struct {
	Data       interface{} `json:"data"`
	Pagination struct {
		Limit   int  `json:"limit"`
		Offset  int  `json:"offset"`
		Total   int  `json:"total,omitempty"`
		HasMore bool `json:"hasMore,omitempty"`
	} `json:"pagination"`
}

type App struct {
	config        *Config
	redisClient   *redis.Client
	httpClient    *fasthttp.Client
	tokenCache    *TokenCache
	tokenCacheHR  *TokenCache
	refreshLock   sync.Mutex
	refreshLockHR sync.Mutex
	startTime     time.Time
}

var ctx = context.Background()

func loadConfig() *Config {
	_ = godotenv.Load()

	return &Config{
		ClientID:          os.Getenv("CLIENT_ID"),
		ClientIDHires:     os.Getenv("CLIENT_ID_HIRES"),
		ClientSecret:      os.Getenv("CLIENT_SECRET"),
		ClientSecretHires: os.Getenv("CLIENT_SECRET_HIRES"),
		RefreshToken:      os.Getenv("TIDAL_REFRESH"),
		RefreshTokenHires: os.Getenv("TIDAL_REFRESH_HIRES"),
		RedisURL:          getEnv("REDIS_URL", "localhost"),
		RedisPort:         getEnv("REDIS_PORT", "6379"),
		RedisPassword:     os.Getenv("REDIS_PASSWORD"),
		UserID:            os.Getenv("USER_ID"),
		Port:              getEnv("PORT", "8000"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func newApp() *App {
	config := loadConfig()

	redisClient := redis.NewClient(&redis.Options{
		Addr:            fmt.Sprintf("%s:%s", config.RedisURL, config.RedisPort),
		Password:        config.RedisPassword,
		DB:              0,
		PoolSize:        redisPoolSize,
		MinIdleConns:    10,
		MaxRetries:      3,
		DialTimeout:     5 * time.Second,
		ReadTimeout:     3 * time.Second,
		WriteTimeout:    3 * time.Second,
		PoolTimeout:     4 * time.Second,
		ConnMaxIdleTime: 5 * time.Minute,
	})

	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := redisClient.Ping(pingCtx).Err(); err != nil {
		log.Printf("Redis connection failed: %v (continuing without Redis cache)", err)
	} else {
		log.Println("Redis connected successfully")
	}

	httpClient := &fasthttp.Client{
		MaxConnsPerHost:               maxConnsPerHost,
		MaxIdleConnDuration:           maxIdleConnDuration,
		MaxConnDuration:               time.Hour,
		ReadTimeout:                   requestTimeout,
		WriteTimeout:                  requestTimeout,
		MaxResponseBodySize:           maxResponseBodySize,
		DisableHeaderNamesNormalizing: true,
		DisablePathNormalizing:        true,
		ReadBufferSize:                8192,
		WriteBufferSize:               8192,
		NoDefaultUserAgentHeader:      false,
	}

	app := &App{
		config:      config,
		redisClient: redisClient,
		httpClient:  httpClient,
		tokenCache: &TokenCache{
			LastCheck: time.Time{},
		},
		tokenCacheHR: &TokenCache{
			LastCheck: time.Time{},
		},
		startTime: time.Now(),
	}

	go func() {
		log.Println("Pre-warming tokens...")
		if _, err := app.getToken(false); err != nil {
			log.Printf("Failed to pre-warm standard token: %v", err)
		}
		if _, err := app.getToken(true); err != nil {
			log.Printf("Failed to pre-warm HiRes token: %v", err)
		}
		log.Println("Token pre-warming complete")
	}()

	return app
}

func (a *App) getToken(hiRes bool) (string, error) {
	cache := a.tokenCache
	lock := &a.refreshLock
	cacheKey := "access_token"

	if hiRes {
		cache = a.tokenCacheHR
		lock = &a.refreshLockHR
		cacheKey = "access_token_hires"
	}

	cache.mu.RLock()
	if cache.Token != "" && time.Now().Before(cache.ExpiresAt) {
		token := cache.Token
		cache.mu.RUnlock()
		return token, nil
	}
	cache.mu.RUnlock()

	lock.Lock()
	defer lock.Unlock()

	cache.mu.RLock()
	if cache.Token != "" && time.Now().Before(cache.ExpiresAt) {
		token := cache.Token
		cache.mu.RUnlock()
		return token, nil
	}
	cache.mu.RUnlock()

	if token, err := a.redisClient.Get(ctx, cacheKey).Result(); err == nil && token != "" {
		needsCheck := time.Since(cache.LastCheck) > tokenCheckInterval

		if !needsCheck || a.quickTokenCheck(token) {
			cache.mu.Lock()
			cache.Token = token
			cache.ExpiresAt = time.Now().Add(tokenCacheDuration)
			cache.LastCheck = time.Now()
			cache.mu.Unlock()

			log.Printf("Using cached %s token", cacheKey)
			return token, nil
		}
	}

	log.Printf("Refreshing %s token...", cacheKey)
	token, expiresIn, err := a.refreshToken(hiRes)
	if err != nil {
		return "", err
	}

	expiryDuration := time.Duration(expiresIn) * time.Second
	if expiryDuration > tokenCacheDuration {
		expiryDuration = tokenCacheDuration
	}

	cache.mu.Lock()
	cache.Token = token
	cache.ExpiresAt = time.Now().Add(expiryDuration)
	cache.LastCheck = time.Now()
	cache.mu.Unlock()

	a.redisClient.Set(ctx, cacheKey, token, expiryDuration)

	log.Printf("Token refreshed successfully (expires in %s)", expiryDuration)
	return token, nil
}

func (a *App) quickTokenCheck(token string) bool {
	checkURL := fmt.Sprintf("https://api.tidal.com/v2/feed/activities/?userId=%s&limit=1", a.config.UserID)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(checkURL)
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set("Authorization", "Bearer "+token)

	if err := a.httpClient.DoTimeout(req, resp, 5*time.Second); err != nil {
		return false
	}

	return resp.StatusCode() == fasthttp.StatusOK
}

func (a *App) refreshToken(hiRes bool) (string, int, error) {
	clientID := a.config.ClientID
	clientSecret := a.config.ClientSecret
	refreshToken := a.config.RefreshToken

	if hiRes {
		clientID = a.config.ClientIDHires
		clientSecret = a.config.ClientSecretHires
		refreshToken = a.config.RefreshTokenHires
	}

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")
	form.Set("scope", "r_usr+w_usr+w_sub")

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://auth.tidal.com/v1/oauth2/token")
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString(form.Encode())

	auth := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req.Header.Set("Authorization", "Basic "+auth)

	if err := a.httpClient.DoTimeout(req, resp, requestTimeout); err != nil {
		return "", 0, fmt.Errorf("token refresh failed: %w", err)
	}

	if resp.StatusCode() != fasthttp.StatusOK {
		return "", 0, fmt.Errorf("token refresh failed with status %d: %s", resp.StatusCode(), resp.Body())
	}

	var tokenResp TokenResponse
	if err := fastJSON.Unmarshal(resp.Body(), &tokenResp); err != nil {
		return "", 0, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return "", 0, fmt.Errorf("empty access token received")
	}

	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

func (a *App) makeRequest(reqURL, token string) ([]byte, int, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(reqURL)
	req.Header.SetMethod(fasthttp.MethodGet)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	if err := a.httpClient.DoTimeout(req, resp, requestTimeout); err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		return nil, statusCode, fmt.Errorf("status %d", statusCode)
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	return body, statusCode, nil
}

func (a *App) makeRequestWithHeader(reqURL string, headers map[string]string) ([]byte, int, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(reqURL)
	req.Header.SetMethod(fasthttp.MethodGet)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if err := a.httpClient.DoTimeout(req, resp, requestTimeout); err != nil {
		return nil, 0, fmt.Errorf("request failed: %w", err)
	}

	statusCode := resp.StatusCode()
	if statusCode != fasthttp.StatusOK {
		return nil, statusCode, fmt.Errorf("status %d", statusCode)
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())

	return body, statusCode, nil
}

func parsePagination(c *fiber.Ctx) PaginationParams {
	limit := c.QueryInt("limit", defaultLimit)
	offset := c.QueryInt("offset", defaultOffset)

	if limit < 1 {
		limit = defaultLimit
	}
	if limit > maxLimit {
		limit = maxLimit
	}
	if offset < 0 {
		offset = defaultOffset
	}

	return PaginationParams{
		Limit:  limit,
		Offset: offset,
	}
}

func createPaginatedResponse(data interface{}, limit, offset, total int) PaginatedResponse {
	resp := PaginatedResponse{
		Data: data,
	}
	resp.Pagination.Limit = limit
	resp.Pagination.Offset = offset
	resp.Pagination.Total = total
	resp.Pagination.HasMore = offset+limit < total

	return resp
}

func (a *App) indexHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"name":    "HiFi-RestAPI",
		"version": "v2.0",
		"repo":    "https://github.com/eduardprigoana/hifi-go",
		"status":  "operational",
	})
}

func (a *App) dashHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	quality := c.Query("quality", "HI_RES_LOSSLESS")

	if id == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}

	token, err := a.getToken(true)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	trackURL := fmt.Sprintf("https://tidal.com/v1/tracks/%d/playbackinfo?audioquality=%s&playbackmode=STREAM&assetpresentation=FULL", id, quality)
	data, statusCode, err := a.makeRequest(trackURL, token)

	if err != nil {
		if statusCode == 404 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "track not found or quality unavailable"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch track"})
	}

	var result map[string]interface{}
	if err := fastJSON.Unmarshal(data, &result); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "invalid response"})
	}

	manifestStr, ok := result["manifest"].(string)
	if !ok {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "manifest not found"})
	}

	decoded, err := base64.StdEncoding.DecodeString(manifestStr)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "manifest decode failed"})
	}

	mimeType, _ := result["manifestMimeType"].(string)
	if mimeType == "" {
		mimeType = "application/dash+xml"
	}

	c.Set(fiber.HeaderContentType, mimeType)
	c.Set(fiber.HeaderCacheControl, "public, max-age=3600")
	return c.Send(decoded)
}

func (a *App) trackHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	quality := c.Query("quality", "LOSSLESS")

	if id == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}

	if quality == "HI_RES_LOSSLESS" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "HI_RES_LOSSLESS not supported on this endpoint",
			"hint":  "Use /dash/ endpoint for HI_RES_LOSSLESS quality",
		})
	}

	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	trackURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/playbackinfopostpaywall/v4?audioquality=%s&playbackmode=STREAM&assetpresentation=FULL", id, quality)
	infoURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/?countryCode=US", id)

	var trackData, infoData []byte
	var trackErr, infoErr error
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		trackData, _, trackErr = a.makeRequest(trackURL, token)
	}()

	go func() {
		defer wg.Done()
		infoData, _, infoErr = a.makeRequest(infoURL, token)
	}()

	wg.Wait()

	if trackErr != nil || infoErr != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "track not found or quality unavailable"})
	}

	var trackResult, infoResult map[string]interface{}
	fastJSON.Unmarshal(trackData, &trackResult)
	fastJSON.Unmarshal(infoData, &infoResult)

	manifestStr, _ := trackResult["manifest"].(string)
	decoded, _ := base64.StdEncoding.DecodeString(manifestStr)

	var manifestJSON map[string]interface{}
	fastJSON.Unmarshal(decoded, &manifestJSON)

	audioURL := ""
	if urls, ok := manifestJSON["urls"].([]interface{}); ok && len(urls) > 0 {
		audioURL, _ = urls[0].(string)
	}

	return c.JSON(fiber.Map{
		"track":    infoResult,
		"playback": trackResult,
		"url":      audioURL,
	})
}

func (a *App) lyricsHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	if id == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}

	token, _ := a.getToken(false)
	lyricsURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/lyrics?countryCode=US&locale=en_US&deviceType=BROWSER", id)

	data, statusCode, err := a.makeRequest(lyricsURL, token)
	if err != nil {
		if statusCode == 404 {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "lyrics not found"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch lyrics"})
	}

	var result map[string]interface{}
	fastJSON.Unmarshal(data, &result)
	return c.JSON(result)
}

func (a *App) songHandler(c *fiber.Ctx) error {
	q := c.Query("q")
	quality := c.Query("quality", "LOSSLESS")

	if q == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "q parameter required"})
	}

	token, _ := a.getToken(false)
	searchURL := fmt.Sprintf("https://api.tidal.com/v1/search/tracks?countryCode=US&query=%s", url.QueryEscape(q))

	searchData, _, err := a.makeRequest(searchURL, token)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "search failed"})
	}

	var searchResult map[string]interface{}
	fastJSON.Unmarshal(searchData, &searchResult)

	items, _ := searchResult["items"].([]interface{})
	if len(items) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "no results found"})
	}

	firstItem, _ := items[0].(map[string]interface{})
	trackID := int(firstItem["id"].(float64))

	trackURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/playbackinfopostpaywall/v4?audioquality=%s&playbackmode=STREAM&assetpresentation=FULL", trackID, quality)
	trackData, _, _ := a.makeRequest(trackURL, token)

	var trackResult map[string]interface{}
	fastJSON.Unmarshal(trackData, &trackResult)

	manifestStr, _ := trackResult["manifest"].(string)
	decoded, _ := base64.StdEncoding.DecodeString(manifestStr)

	var manifestJSON map[string]interface{}
	fastJSON.Unmarshal(decoded, &manifestJSON)

	audioURL := ""
	if urls, ok := manifestJSON["urls"].([]interface{}); ok && len(urls) > 0 {
		audioURL, _ = urls[0].(string)
	}

	return c.JSON(fiber.Map{
		"track":    firstItem,
		"playback": trackResult,
		"url":      audioURL,
	})
}

func (a *App) searchHandler(c *fiber.Ctx) error {
	s := c.Query("s")
	artist := c.Query("a")
	album := c.Query("al")
	video := c.Query("v")
	playlist := c.Query("p")

	pagination := parsePagination(c)

	token, _ := a.getToken(false)
	var searchURL string
	var searchType string

	switch {
	case s != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/tracks?query=%s&limit=%d&offset=%d&countryCode=US",
			url.QueryEscape(s), pagination.Limit, pagination.Offset)
		searchType = "tracks"
	case artist != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=ARTISTS,TRACKS&countryCode=US",
			url.QueryEscape(artist), pagination.Limit, pagination.Offset)
		searchType = "artists"
	case album != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=ALBUMS&countryCode=US",
			url.QueryEscape(album), pagination.Limit, pagination.Offset)
		searchType = "albums"
	case video != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=VIDEOS&countryCode=US",
			url.QueryEscape(video), pagination.Limit, pagination.Offset)
		searchType = "videos"
	case playlist != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=PLAYLISTS&countryCode=US",
			url.QueryEscape(playlist), pagination.Limit, pagination.Offset)
		searchType = "playlists"
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "search parameter required (s, a, al, v, or p)"})
	}

	data, _, err := a.makeRequest(searchURL, token)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "search failed"})
	}

	var result map[string]interface{}
	fastJSON.Unmarshal(data, &result)

	var items []interface{}
	var total int

	if searchType == "tracks" {
		items, _ = result["items"].([]interface{})
		if totalCount, ok := result["totalNumberOfItems"].(float64); ok {
			total = int(totalCount)
		}
	} else {
		items, _ = result["items"].([]interface{})
		total = len(items)
	}

	response := createPaginatedResponse(items, pagination.Limit, pagination.Offset, total)
	return c.JSON(response)
}

func (a *App) albumHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	if id == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}

	pagination := parsePagination(c)
	token, _ := a.getToken(false)

	albumURL := fmt.Sprintf("https://api.tidal.com/v1/albums/%d/?countryCode=US", id)
	itemsURL := fmt.Sprintf("https://api.tidal.com/v1/albums/%d/items?limit=%d&offset=%d&countryCode=US",
		id, pagination.Limit, pagination.Offset)

	var albumData, itemsData []byte
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		albumData, _, _ = a.makeRequest(albumURL, token)
	}()

	go func() {
		defer wg.Done()
		itemsData, _, _ = a.makeRequest(itemsURL, token)
	}()

	wg.Wait()

	var albumResult, itemsResult map[string]interface{}
	fastJSON.Unmarshal(albumData, &albumResult)
	fastJSON.Unmarshal(itemsData, &itemsResult)

	items, _ := itemsResult["items"].([]interface{})
	total := 0
	if totalCount, ok := itemsResult["totalNumberOfItems"].(float64); ok {
		total = int(totalCount)
	}

	response := fiber.Map{
		"album": albumResult,
		"items": createPaginatedResponse(items, pagination.Limit, pagination.Offset, total),
	}

	return c.JSON(response)
}

func (a *App) playlistHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}

	pagination := parsePagination(c)
	token, _ := a.getToken(false)

	playlistURL := fmt.Sprintf("https://api.tidal.com/v1/playlists/%s?countryCode=US", id)
	itemsURL := fmt.Sprintf("https://api.tidal.com/v1/playlists/%s/items?countryCode=US&limit=%d&offset=%d",
		id, pagination.Limit, pagination.Offset)

	var playlistData, itemsData []byte
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		playlistData, _, _ = a.makeRequest(playlistURL, token)
	}()

	go func() {
		defer wg.Done()
		itemsData, _, _ = a.makeRequest(itemsURL, token)
	}()

	wg.Wait()

	var playlistResult, itemsResult map[string]interface{}
	fastJSON.Unmarshal(playlistData, &playlistResult)
	fastJSON.Unmarshal(itemsData, &itemsResult)

	items, _ := itemsResult["items"].([]interface{})
	total := 0
	if totalCount, ok := itemsResult["totalNumberOfItems"].(float64); ok {
		total = int(totalCount)
	}

	response := fiber.Map{
		"playlist": playlistResult,
		"items":    createPaginatedResponse(items, pagination.Limit, pagination.Offset, total),
	}

	return c.JSON(response)
}

func (a *App) artistHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	f := c.QueryInt("f", 0)

	if id == 0 && f == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id or f parameter required"})
	}

	token, _ := a.getToken(false)

	if id > 0 {
		artistURL := fmt.Sprintf("https://api.tidal.com/v1/artists/%d?countryCode=US", id)
		data, statusCode, err := a.makeRequest(artistURL, token)

		if err != nil && statusCode == 404 {
			altURL := fmt.Sprintf("https://api.tidal.com/v1/pages/artist?artistId=%d&countryCode=US&locale=en_US&deviceType=BROWSER", id)
			data, _, _ = a.makeRequest(altURL, token)
			var result map[string]interface{}
			fastJSON.Unmarshal(data, &result)
			return c.JSON(result)
		}

		var artistResult map[string]interface{}
		fastJSON.Unmarshal(data, &artistResult)

		picture, _ := artistResult["picture"].(string)
		name, _ := artistResult["name"].(string)
		artistID, _ := artistResult["id"].(float64)
		artistCover := strings.ReplaceAll(picture, "-", "/")

		imageData := map[string]interface{}{
			"id":   int(artistID),
			"name": name,
			"750":  fmt.Sprintf("https://resources.tidal.com/images/%s/750x750.jpg", artistCover),
			"1080": fmt.Sprintf("https://resources.tidal.com/images/%s/1080x1080.jpg", artistCover),
		}

		return c.JSON(fiber.Map{
			"artist": artistResult,
			"image":  imageData,
		})
	}

	if f > 0 {
		pagination := parsePagination(c)
		artistAlbumsURL := fmt.Sprintf("https://api.tidal.com/v1/pages/single-module-page/ae223310-a4c2-4568-a770-ffef70344441/4/a4f964ba-b52e-41e8-b25c-06cd70c1efad/2?artistId=%d&countryCode=US&deviceType=BROWSER&limit=%d&offset=%d",
			f, pagination.Limit, pagination.Offset)
		albumData, _, _ := a.makeRequest(artistAlbumsURL, token)

		var albumsResult map[string]interface{}
		fastJSON.Unmarshal(albumData, &albumsResult)
		return c.JSON(albumsResult)
	}

	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid parameters"})
}

func (a *App) coverHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	q := c.Query("q")

	if id == 0 && q == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id or q parameter required"})
	}

	token, _ := a.getToken(false)

	if id > 0 {
		trackURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/?countryCode=US", id)
		data, _, err := a.makeRequest(trackURL, token)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "track not found"})
		}

		var trackResult map[string]interface{}
		fastJSON.Unmarshal(data, &trackResult)

		album, _ := trackResult["album"].(map[string]interface{})
		albumID, _ := album["id"].(float64)
		title, _ := album["title"].(string)
		cover, _ := album["cover"].(string)
		coverPath := strings.ReplaceAll(cover, "-", "/")

		return c.JSON(map[string]interface{}{
			"id":   int(albumID),
			"name": title,
			"1280": fmt.Sprintf("https://resources.tidal.com/images/%s/1280x1280.jpg", coverPath),
			"640":  fmt.Sprintf("https://resources.tidal.com/images/%s/640x640.jpg", coverPath),
			"320":  fmt.Sprintf("https://resources.tidal.com/images/%s/320x320.jpg", coverPath),
			"80":   fmt.Sprintf("https://resources.tidal.com/images/%s/80x80.jpg", coverPath),
		})
	}

	pagination := parsePagination(c)
	searchURL := fmt.Sprintf("https://api.tidal.com/v1/search/tracks?countryCode=US&query=%s&limit=%d&offset=%d",
		url.QueryEscape(q), pagination.Limit, pagination.Offset)
	data, _, err := a.makeRequest(searchURL, token)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "search failed"})
	}

	var searchResult map[string]interface{}
	fastJSON.Unmarshal(data, &searchResult)

	items, _ := searchResult["items"].([]interface{})
	jsonData := make([]map[string]interface{}, 0, len(items))

	for _, item := range items {
		track, _ := item.(map[string]interface{})
		trackID, _ := track["id"].(float64)
		title, _ := track["title"].(string)
		album, _ := track["album"].(map[string]interface{})
		cover, _ := album["cover"].(string)
		coverPath := strings.ReplaceAll(cover, "-", "/")

		jsonData = append(jsonData, map[string]interface{}{
			"id":   int(trackID),
			"name": title,
			"1280": fmt.Sprintf("https://resources.tidal.com/images/%s/1280x1280.jpg", coverPath),
			"640":  fmt.Sprintf("https://resources.tidal.com/images/%s/640x640.jpg", coverPath),
			"320":  fmt.Sprintf("https://resources.tidal.com/images/%s/320x320.jpg", coverPath),
			"80":   fmt.Sprintf("https://resources.tidal.com/images/%s/80x80.jpg", coverPath),
		})
	}

	total := 0
	if totalCount, ok := searchResult["totalNumberOfItems"].(float64); ok {
		total = int(totalCount)
	}

	response := createPaginatedResponse(jsonData, pagination.Limit, pagination.Offset, total)
	return c.JSON(response)
}

func (a *App) homeHandler(c *fiber.Ctx) error {
	country := strings.ToUpper(c.Query("country", "US"))
	token, _ := a.getToken(false)

	homeURL := fmt.Sprintf("https://api.tidal.com/v1/pages/home?countryCode=%s&deviceType=BROWSER", country)
	data, _, err := a.makeRequest(homeURL, token)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch home"})
	}

	var result map[string]interface{}
	fastJSON.Unmarshal(data, &result)
	return c.JSON(result)
}

func (a *App) mixHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	country := strings.ToUpper(c.Query("country", "US"))

	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}

	pagination := parsePagination(c)
	mixURL := fmt.Sprintf("https://api.tidal.com/v1/mixes/%s/items?countryCode=%s&limit=%d&offset=%d",
		id, country, pagination.Limit, pagination.Offset)

	headers := map[string]string{
		"x-tidal-token": a.config.ClientID,
	}

	data, _, err := a.makeRequestWithHeader(mixURL, headers)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "request failed"})
	}

	var result map[string]interface{}
	fastJSON.Unmarshal(data, &result)

	items, _ := result["items"].([]interface{})
	total := 0
	if totalCount, ok := result["totalNumberOfItems"].(float64); ok {
		total = int(totalCount)
	}

	response := createPaginatedResponse(items, pagination.Limit, pagination.Offset, total)
	return c.JSON(response)
}

func main() {
	app := newApp()
	defer app.redisClient.Close()

	fiberApp := fiber.New(fiber.Config{
		Prefork:               false,
		CaseSensitive:         true,
		StrictRouting:         false,
		ServerHeader:          "HiFi-Go",
		AppName:               "HiFi-RestAPI v2.0",
		BodyLimit:             50 * 1024 * 1024,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           120 * time.Second,
		DisableStartupMessage: false,
		EnablePrintRoutes:     false,
		JSONEncoder:           fastJSON.Marshal,
		JSONDecoder:           fastJSON.Unmarshal,
	})

	fiberApp.Use(recover.New(recover.Config{
		EnableStackTrace: true,
	}))

	fiberApp.Use(logger.New(logger.Config{
		Format:     "${time} | ${status} | ${latency} | ${method} ${path}\n",
		TimeFormat: "15:04:05",
		TimeZone:   "Local",
	}))

	fiberApp.Use(compress.New(compress.Config{
		Level: compress.LevelBestSpeed,
	}))

	fiberApp.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowMethods:     "GET,POST,HEAD,OPTIONS",
		AllowHeaders:     "*",
		AllowCredentials: false,
		ExposeHeaders:    "*",
		MaxAge:           86400,
	}))

	fiberApp.Use(limiter.New(limiter.Config{
		Max:        100,
		Expiration: 1 * time.Minute,
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error": "rate limit exceeded",
			})
		},
	}))

	fiberApp.Get("/", app.indexHandler)
	fiberApp.Get("/dash/", app.dashHandler)
	fiberApp.Get("/track/", app.trackHandler)
	fiberApp.Get("/lyrics/", app.lyricsHandler)
	fiberApp.Get("/song/", app.songHandler)
	fiberApp.Get("/search/", app.searchHandler)
	fiberApp.Get("/album/", app.albumHandler)
	fiberApp.Get("/playlist/", app.playlistHandler)
	fiberApp.Get("/artist/", app.artistHandler)
	fiberApp.Get("/cover/", app.coverHandler)
	fiberApp.Get("/home/", app.homeHandler)
	fiberApp.Get("/mix/", app.mixHandler)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		log.Println("Shutting down gracefully...")
		if err := fiberApp.Shutdown(); err != nil {
			log.Printf("Shutdown error: %v", err)
		}
	}()

	log.Printf("Server starting on port %s", app.config.Port)
	log.Printf("API Documentation: https://github.com/eduardprigoana/hifi-go")

	if err := fiberApp.Listen(":" + app.config.Port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
