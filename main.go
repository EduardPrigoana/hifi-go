package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
	"github.com/redis/go-redis/v9"
	"github.com/valyala/fasthttp"
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
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

type App struct {
	config      *Config
	redisClient *redis.Client
	httpClient  *fasthttp.Client
	tokenMutex  sync.RWMutex
	tokenMutex2 sync.RWMutex
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
		Addr:     fmt.Sprintf("%s:%s", config.RedisURL, config.RedisPort),
		Password: config.RedisPassword,
		DB:       0,
		PoolSize: 20,
	})

	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Printf("⚠️  Redis connection failed: %v", err)
	} else {
		log.Println("✅ Redis connected")
	}

	httpClient := &fasthttp.Client{
		MaxConnsPerHost:     1000,
		MaxIdleConnDuration: 90 * time.Second,
		ReadTimeout:         30 * time.Second,
		WriteTimeout:        30 * time.Second,
		MaxResponseBodySize: 100 * 1024 * 1024,
	}

	return &App{
		config:      config,
		redisClient: redisClient,
		httpClient:  httpClient,
	}
}

func (a *App) tokenChecker(token string) bool {
	checkURL := fmt.Sprintf("https://api.tidal.com/v2/feed/activities/?userId=%s", a.config.UserID)

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(checkURL)
	req.Header.SetMethod("GET")
	req.Header.Set("Authorization", "Bearer "+token)

	if err := a.httpClient.DoTimeout(req, resp, 10*time.Second); err != nil {
		return false
	}

	return resp.StatusCode() == 200
}

func (a *App) refresh() (string, error) {
	a.tokenMutex.Lock()
	defer a.tokenMutex.Unlock()

	cachedToken, err := a.redisClient.Get(ctx, "access_token").Result()
	if err == nil && cachedToken != "" {
		if a.tokenChecker(cachedToken) {
			log.Println("✅ Using cached token")
			return cachedToken, nil
		}
		a.redisClient.Del(ctx, "access_token")
	}

	form := url.Values{}
	form.Set("client_id", a.config.ClientID)
	form.Set("refresh_token", a.config.RefreshToken)
	form.Set("grant_type", "refresh_token")
	form.Set("scope", "r_usr+w_usr+w_sub")

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://auth.tidal.com/v1/oauth2/token")
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString(form.Encode())

	auth := base64.StdEncoding.EncodeToString([]byte(a.config.ClientID + ":" + a.config.ClientSecret))
	req.Header.Set("Authorization", "Basic "+auth)

	if err := a.httpClient.DoTimeout(req, resp, 15*time.Second); err != nil {
		return "", err
	}

	if resp.StatusCode() != 200 {
		return "", fmt.Errorf("failed to refresh: %d", resp.StatusCode())
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(resp.Body(), &tokenResp); err != nil {
		return "", err
	}

	a.redisClient.Set(ctx, "access_token", tokenResp.AccessToken, 24*time.Hour)
	log.Println("🔄 Token refreshed")

	return tokenResp.AccessToken, nil
}

func (a *App) refresh2() (string, error) {
	a.tokenMutex2.Lock()
	defer a.tokenMutex2.Unlock()

	cachedToken, err := a.redisClient.Get(ctx, "access_token2").Result()
	if err == nil && cachedToken != "" {
		if a.tokenChecker(cachedToken) {
			log.Println("✅ Using cached HiRes token")
			return cachedToken, nil
		}
		a.redisClient.Del(ctx, "access_token2")
	}

	form := url.Values{}
	form.Set("client_id", a.config.ClientIDHires)
	form.Set("refresh_token", a.config.RefreshTokenHires)
	form.Set("grant_type", "refresh_token")
	form.Set("scope", "r_usr+w_usr+w_sub")

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("https://auth.tidal.com/v1/oauth2/token")
	req.Header.SetMethod("POST")
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString(form.Encode())

	auth := base64.StdEncoding.EncodeToString([]byte(a.config.ClientIDHires + ":" + a.config.ClientSecretHires))
	req.Header.Set("Authorization", "Basic "+auth)

	if err := a.httpClient.DoTimeout(req, resp, 15*time.Second); err != nil {
		return "", err
	}

	if resp.StatusCode() != 200 {
		return "", fmt.Errorf("failed to refresh: %d", resp.StatusCode())
	}

	var tokenResp TokenResponse
	if err := json.Unmarshal(resp.Body(), &tokenResp); err != nil {
		return "", err
	}

	a.redisClient.Set(ctx, "access_token2", tokenResp.AccessToken, 24*time.Hour)
	log.Println("🔄 HiRes token refreshed")

	return tokenResp.AccessToken, nil
}

func (a *App) makeRequest(url, token string) ([]byte, error) {
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(url)
	req.Header.Set("Authorization", "Bearer "+token)

	if err := a.httpClient.DoTimeout(req, resp, 15*time.Second); err != nil {
		return nil, err
	}

	if resp.StatusCode() != 200 {
		return nil, fmt.Errorf("status: %d", resp.StatusCode())
	}

	body := make([]byte, len(resp.Body()))
	copy(body, resp.Body())
	return body, nil
}

// ==================== HANDLERS ====================

func (a *App) indexHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"HIFI-API": "v1.0",
		"Repo":     "https://github.com/sachinsenal0x64/hifi",
	})
}

func (a *App) dashHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	quality := c.Query("quality", "HI_RES_LOSSLESS")

	if id == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "id required"})
	}

	token, err := a.refresh2()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	trackURL := fmt.Sprintf("https://tidal.com/v1/tracks/%d/playbackinfo?audioquality=%s&playbackmode=STREAM&assetpresentation=FULL", id, quality)
	data, err := a.makeRequest(trackURL, token)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Quality not found"})
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)

	manifestStr, ok := result["manifest"].(string)
	if !ok {
		return c.Status(404).JSON(fiber.Map{"error": "Quality not found"})
	}

	decoded, _ := base64.StdEncoding.DecodeString(manifestStr)
	mimeType, _ := result["manifestMimeType"].(string)

	c.Set("Content-Type", mimeType)
	return c.Send(decoded)
}

func (a *App) trackHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	quality := c.Query("quality", "LOSSLESS")

	if id == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "id required"})
	}

	if quality == "HI_RES_LOSSLESS" {
		return c.Status(404).JSON(fiber.Map{"error": "Use /dash/ for HI_RES_LOSSLESS"})
	}

	token, err := a.refresh()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": err.Error()})
	}

	trackURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/playbackinfopostpaywall/v4?audioquality=%s&playbackmode=STREAM&assetpresentation=FULL", id, quality)
	infoURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/?countryCode=US", id)

	var trackData, infoData []byte
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		trackData, _ = a.makeRequest(trackURL, token)
	}()

	go func() {
		defer wg.Done()
		infoData, _ = a.makeRequest(infoURL, token)
	}()

	wg.Wait()

	var trackResult, infoResult map[string]interface{}
	json.Unmarshal(trackData, &trackResult)
	json.Unmarshal(infoData, &infoResult)

	manifestStr, _ := trackResult["manifest"].(string)
	decoded, _ := base64.StdEncoding.DecodeString(manifestStr)

	var manifestJSON map[string]interface{}
	json.Unmarshal(decoded, &manifestJSON)

	audioURL := ""
	if urls, ok := manifestJSON["urls"].([]interface{}); ok && len(urls) > 0 {
		audioURL, _ = urls[0].(string)
	}

	return c.JSON([]interface{}{
		infoResult,
		trackResult,
		fiber.Map{"OriginalTrackUrl": audioURL},
	})
}

func (a *App) lyricsHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	if id == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "id required"})
	}

	token, _ := a.refresh()
	url := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/lyrics?countryCode=US&locale=en_US&deviceType=BROWSER", id)
	data, err := a.makeRequest(url, token)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Lyrics not found"})
	}

	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return c.JSON([]interface{}{result})
}

func (a *App) songHandler(c *fiber.Ctx) error {
	q := c.Query("q")
	quality := c.Query("quality", "LOSSLESS")

	if q == "" {
		return c.Status(400).JSON(fiber.Map{"error": "q required"})
	}

	token, _ := a.refresh()
	searchURL := fmt.Sprintf("https://api.tidal.com/v1/search/tracks?countryCode=US&query=%s", url.QueryEscape(q))
	searchData, err := a.makeRequest(searchURL, token)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "Not found"})
	}

	var searchResult map[string]interface{}
	json.Unmarshal(searchData, &searchResult)

	items, _ := searchResult["items"].([]interface{})
	if len(items) == 0 {
		return c.Status(404).JSON(fiber.Map{"error": "No results"})
	}

	firstItem, _ := items[0].(map[string]interface{})
	trackID := int(firstItem["id"].(float64))

	trackURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/playbackinfopostpaywall/v4?audioquality=%s&playbackmode=STREAM&assetpresentation=FULL", trackID, quality)
	trackData, _ := a.makeRequest(trackURL, token)

	var trackResult map[string]interface{}
	json.Unmarshal(trackData, &trackResult)

	manifestStr, _ := trackResult["manifest"].(string)
	decoded, _ := base64.StdEncoding.DecodeString(manifestStr)

	var manifestJSON map[string]interface{}
	json.Unmarshal(decoded, &manifestJSON)

	audioURL := ""
	if urls, ok := manifestJSON["urls"].([]interface{}); ok && len(urls) > 0 {
		audioURL, _ = urls[0].(string)
	}

	return c.JSON([]interface{}{
		firstItem,
		trackResult,
		fiber.Map{"OriginalTrackUrl": audioURL},
	})
}

func (a *App) searchHandler(c *fiber.Ctx) error {
	s := c.Query("s")
	artist := c.Query("a")
	album := c.Query("al")
	video := c.Query("v")
	playlist := c.Query("p")
	limit := c.QueryInt("li", 25)
	offset := c.QueryInt("o", 0)

	token, _ := a.refresh()
	var searchURL string

	switch {
	case s != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/tracks?query=%s&limit=%d&offset=%d&countryCode=US", url.QueryEscape(s), limit, offset)
	case artist != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=ARTISTS,TRACKS&countryCode=US", url.QueryEscape(artist), limit, offset)
	case album != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=ALBUMS&countryCode=US", url.QueryEscape(album), limit, offset)
	case video != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=VIDEOS&countryCode=US", url.QueryEscape(video), limit, offset)
	case playlist != "":
		searchURL = fmt.Sprintf("https://api.tidal.com/v1/search/top-hits?query=%s&limit=%d&offset=%d&types=PLAYLISTS&countryCode=US", url.QueryEscape(playlist), limit, offset)
	default:
		return c.Status(404).JSON(fiber.Map{"error": "No search parameter"})
	}

	data, _ := a.makeRequest(searchURL, token)
	var result interface{}
	json.Unmarshal(data, &result)

	if artist != "" {
		return c.JSON([]interface{}{result})
	}
	return c.JSON(result)
}

func (a *App) albumHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	if id == 0 {
		return c.Status(400).JSON(fiber.Map{"error": "id required"})
	}

	token, _ := a.refresh()
	albumURL := fmt.Sprintf("https://api.tidal.com/v1/albums/%d/?countryCode=US", id)
	itemsURL := fmt.Sprintf("https://api.tidal.com/v1/albums/%d/items?limit=100&countryCode=US", id)

	var albumData, itemsData []byte
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		albumData, _ = a.makeRequest(albumURL, token)
	}()

	go func() {
		defer wg.Done()
		itemsData, _ = a.makeRequest(itemsURL, token)
	}()

	wg.Wait()

	var albumResult, itemsResult map[string]interface{}
	json.Unmarshal(albumData, &albumResult)
	json.Unmarshal(itemsData, &itemsResult)

	return c.JSON([]interface{}{albumResult, itemsResult})
}

func (a *App) playlistHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(400).JSON(fiber.Map{"error": "id required"})
	}

	token, _ := a.refresh()
	playlistURL := fmt.Sprintf("https://api.tidal.com/v1/playlists/%s?countryCode=US", id)
	itemsURL := fmt.Sprintf("https://api.tidal.com/v1/playlists/%s/items?countryCode=US&limit=100", id)

	var playlistData, itemsData []byte
	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		playlistData, _ = a.makeRequest(playlistURL, token)
	}()

	go func() {
		defer wg.Done()
		itemsData, _ = a.makeRequest(itemsURL, token)
	}()

	wg.Wait()

	var playlistResult, itemsResult map[string]interface{}
	json.Unmarshal(playlistData, &playlistResult)
	json.Unmarshal(itemsData, &itemsResult)

	return c.JSON([]interface{}{playlistResult, itemsResult})
}

func (a *App) artistHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	f := c.QueryInt("f", 0)

	token, _ := a.refresh()

	if id > 0 {
		artistURL := fmt.Sprintf("https://api.tidal.com/v1/artists/%d?countryCode=US", id)
		data, err := a.makeRequest(artistURL, token)

		if err != nil {
			altURL := fmt.Sprintf("https://api.tidal.com/v1/pages/artist?artistId=%d&countryCode=US&locale=en_US&deviceType=BROWSER", id)
			data, _ = a.makeRequest(altURL, token)
			var result map[string]interface{}
			json.Unmarshal(data, &result)
			return c.JSON([]interface{}{result})
		}

		var artistResult map[string]interface{}
		json.Unmarshal(data, &artistResult)

		picture, _ := artistResult["picture"].(string)
		name, _ := artistResult["name"].(string)
		artistID, _ := artistResult["id"].(float64)
		artistCover := strings.ReplaceAll(picture, "-", "/")

		jsonData := []map[string]interface{}{
			{
				"id":   int(artistID),
				"name": name,
				"750":  fmt.Sprintf("https://resources.tidal.com/images/%s/750x750.jpg", artistCover),
			},
		}

		return c.JSON([]interface{}{artistResult, jsonData})
	}

	if f > 0 {
		artistAlbumsURL := fmt.Sprintf("https://api.tidal.com/v1/pages/single-module-page/ae223310-a4c2-4568-a770-ffef70344441/4/a4f964ba-b52e-41e8-b25c-06cd70c1efad/2?artistId=%d&countryCode=US&deviceType=BROWSER", f)
		albumData, _ := a.makeRequest(artistAlbumsURL, token)

		var albumsResult map[string]interface{}
		json.Unmarshal(albumData, &albumsResult)
		return c.JSON([]interface{}{albumsResult})
	}

	return c.Status(400).JSON(fiber.Map{"error": "id or f required"})
}

func (a *App) coverHandler(c *fiber.Ctx) error {
	id := c.QueryInt("id", 0)
	q := c.Query("q")

	token, _ := a.refresh()

	if id > 0 {
		trackURL := fmt.Sprintf("https://api.tidal.com/v1/tracks/%d/?countryCode=US", id)
		data, _ := a.makeRequest(trackURL, token)

		var trackResult map[string]interface{}
		json.Unmarshal(data, &trackResult)

		album, _ := trackResult["album"].(map[string]interface{})
		albumID, _ := album["id"].(float64)
		title, _ := album["title"].(string)
		cover, _ := album["cover"].(string)
		coverPath := strings.ReplaceAll(cover, "-", "/")

		return c.JSON([]map[string]interface{}{
			{
				"id":   int(albumID),
				"name": title,
				"1280": fmt.Sprintf("https://resources.tidal.com/images/%s/1280x1280.jpg", coverPath),
				"640":  fmt.Sprintf("https://resources.tidal.com/images/%s/640x640.jpg", coverPath),
				"80":   fmt.Sprintf("https://resources.tidal.com/images/%s/80x80.jpg", coverPath),
			},
		})
	}

	if q != "" {
		searchURL := fmt.Sprintf("https://api.tidal.com/v1/search/tracks?countryCode=US&query=%s", url.QueryEscape(q))
		data, _ := a.makeRequest(searchURL, token)

		var searchResult map[string]interface{}
		json.Unmarshal(data, &searchResult)

		items, _ := searchResult["items"].([]interface{})
		var jsonData []map[string]interface{}

		for i, item := range items {
			if i >= 10 {
				break
			}
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
				"80":   fmt.Sprintf("https://resources.tidal.com/images/%s/80x80.jpg", coverPath),
			})
		}

		return c.JSON(jsonData)
	}

	return c.Status(404).JSON(fiber.Map{"error": "Cover not found"})
}

func (a *App) homeHandler(c *fiber.Ctx) error {
	country := c.Query("country", "US")
	token, _ := a.refresh()

	homeURL := fmt.Sprintf("https://api.tidal.com/v1/pages/home?countryCode=%s&deviceType=BROWSER", strings.ToUpper(country))
	data, _ := a.makeRequest(homeURL, token)

	var result map[string]interface{}
	json.Unmarshal(data, &result)
	return c.JSON(result)
}

func (a *App) mixHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	country := c.Query("country", "US")

	if id == "" {
		return c.Status(400).JSON(fiber.Map{"error": "id required"})
	}

	mixURL := fmt.Sprintf("https://api.tidal.com/v1/mixes/%s/items?countryCode=%s", id, strings.ToUpper(country))

	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI(mixURL)
	req.Header.Set("x-tidal-token", a.config.ClientID)

	a.httpClient.DoTimeout(req, resp, 15*time.Second)

	var result map[string]interface{}
	json.Unmarshal(resp.Body(), &result)
	return c.JSON(result)
}

func main() {
	app := newApp()
	defer app.redisClient.Close()

	fiberApp := fiber.New(fiber.Config{
		Prefork:       false, // Set true for multi-core production
		CaseSensitive: true,
		ServerHeader:  "HiFi-RestAPI",
		AppName:       "HiFi-RestAPI v1.0",
		BodyLimit:     100 * 1024 * 1024,
	})

	fiberApp.Use(recover.New())
	fiberApp.Use(cors.New(cors.Config{
		AllowOrigins:     "*",
		AllowMethods:     "GET,POST,HEAD,PUT,DELETE,PATCH,OPTIONS",
		AllowHeaders:     "*",
		AllowCredentials: false,
		ExposeHeaders:    "*",
	}))

	// Routes
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

	port := getEnv("PORT", "8000")
	log.Printf("🚀 Server starting on port %s", port)
	log.Fatal(fiberApp.Listen(":" + port))
}
