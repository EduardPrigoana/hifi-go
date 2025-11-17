package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/joho/godotenv"
	jsoniter "github.com/json-iterator/go"
	"github.com/valyala/fasthttp"
)

var fastJSON = jsoniter.ConfigCompatibleWithStandardLibrary

const (
	requestTimeout      = 15 * time.Second
	maxConnsPerHost     = 2000
	maxIdleConnDuration = 90 * time.Second
	maxResponseBodySize = 100 * 1024 * 1024
)

type Config struct {
	ClientID, ClientIDHires, ClientSecret, ClientSecretHires, RefreshToken, RefreshTokenHires, UserID, Port string
}

type TokenCache struct {
	Token string
	mu    sync.RWMutex
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

type App struct {
	config        *Config
	httpClient    *fasthttp.Client
	tokenCache    *TokenCache
	tokenCacheHR  *TokenCache
	refreshLock   sync.Mutex
	refreshLockHR sync.Mutex
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

	httpClient := &fasthttp.Client{
		MaxConnsPerHost:     maxConnsPerHost,
		MaxIdleConnDuration: maxIdleConnDuration,
		ReadTimeout:         requestTimeout,
		WriteTimeout:        requestTimeout,
		MaxResponseBodySize: maxResponseBodySize,
	}
	app := &App{
		config:       config,
		httpClient:   httpClient,
		tokenCache:   &TokenCache{},
		tokenCacheHR: &TokenCache{},
	}

	return app
}

func (a *App) tokenCheck(token string) bool {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() { fasthttp.ReleaseRequest(req); fasthttp.ReleaseResponse(resp) }()

	var sb strings.Builder
	sb.WriteString("https://api.tidal.com/v2/feed/activities?userId=")
	sb.WriteString(a.config.UserID)
	sb.WriteString("&limit=1")
	req.SetRequestURI(sb.String())
	req.Header.Set("Authorization", "Bearer "+token)

	err := a.httpClient.DoTimeout(req, resp, 5*time.Second)
	statusCode := resp.StatusCode()

	log.Printf("Tidal API status: %d", statusCode)

	return err == nil && statusCode == fasthttp.StatusOK
}

func (a *App) getToken(hiRes bool) (string, error) {
	cache, lock := a.tokenCache, &a.refreshLock
	if hiRes {
		cache, lock = a.tokenCacheHR, &a.refreshLockHR
	}

	cache.mu.RLock()
	cachedToken := cache.Token
	cache.mu.RUnlock()

	if cachedToken != "" {
		log.Println("🔍 Found cached token. Checking validity...")
		if a.tokenCheck(cachedToken) {
			log.Println("✅ Using cached token")
			return cachedToken, nil
		}
		log.Println("⚠️ Cached token invalid or expired — refreshing...")
		cache.mu.Lock()
		cache.Token = ""
		cache.mu.Unlock()
	}

	lock.Lock()
	defer lock.Unlock()

	cache.mu.RLock()
	cachedToken = cache.Token
	cache.mu.RUnlock()

	if cachedToken != "" {
		log.Println("🔍 Found cached token. Checking validity...")
		if a.tokenCheck(cachedToken) {
			log.Println("✅ Using cached token")
			return cachedToken, nil
		}
		log.Println("⚠️ Cached token invalid or expired — refreshing...")
	}

	token, _, err := a.refreshToken(hiRes)
	if err != nil {
		return "", fmt.Errorf("token refresh failed: %w", err)
	}

	cache.mu.Lock()
	cache.Token = token
	cache.mu.Unlock()

	log.Println("🔄 Token refreshed and cached.")
	return token, nil
}

func (a *App) refreshToken(hiRes bool) (string, int, error) {
	clientID, clientSecret, refreshToken := a.config.ClientID, a.config.ClientSecret, a.config.RefreshToken
	if hiRes {
		clientID, clientSecret, refreshToken = a.config.ClientIDHires, a.config.ClientSecretHires, a.config.RefreshTokenHires
	}

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("refresh_token", refreshToken)
	form.Set("grant_type", "refresh_token")
	form.Set("scope", "r_usr+w_usr+w_sub")

	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() { fasthttp.ReleaseRequest(req); fasthttp.ReleaseResponse(resp) }()

	req.SetRequestURI("https://auth.tidal.com/v1/oauth2/token")
	req.Header.SetMethod(fasthttp.MethodPost)
	req.Header.SetContentType("application/x-www-form-urlencoded")
	req.SetBodyString(form.Encode())
	auth := base64.StdEncoding.EncodeToString([]byte(clientID + ":" + clientSecret))
	req.Header.Set("Authorization", "Basic "+auth)

	if err := a.httpClient.DoTimeout(req, resp, requestTimeout); err != nil {
		return "", 0, err
	}
	if resp.StatusCode() != fasthttp.StatusOK {
		return "", 0, fmt.Errorf("status %d: %s", resp.StatusCode(), resp.Body())
	}

	var tokenResp TokenResponse
	if err := fastJSON.Unmarshal(resp.Body(), &tokenResp); err != nil {
		return "", 0, err
	}
	return tokenResp.AccessToken, tokenResp.ExpiresIn, nil
}

func (a *App) makeRequest(reqURL, token string) ([]byte, int, error) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() { fasthttp.ReleaseRequest(req); fasthttp.ReleaseResponse(resp) }()

	req.SetRequestURI(reqURL)
	req.Header.Set("Authorization", "Bearer "+token)

	if err := a.httpClient.DoTimeout(req, resp, requestTimeout); err != nil {
		return nil, 0, err
	}

	body := append([]byte(nil), resp.Body()...)
	return body, resp.StatusCode(), nil
}

func (a *App) makeRequestWithHeader(reqURL string, headers map[string]string) ([]byte, int, error) {
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer func() { fasthttp.ReleaseRequest(req); fasthttp.ReleaseResponse(resp) }()

	req.SetRequestURI(reqURL)
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	if err := a.httpClient.DoTimeout(req, resp, requestTimeout); err != nil {
		return nil, 0, err
	}

	body := append([]byte(nil), resp.Body()...)
	return body, resp.StatusCode(), nil
}

type playbackInfoManifest struct {
	Manifest string `json:"manifest"`
}
type manifestURL struct {
	URLs []string `json:"urls"`
}

func (a *App) indexHandler(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"HIFI-API": "v1.0", "Repo": "https://github.com/sachinsenal0x64/hifi"})
}

func (a *App) dashHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}
	token, err := a.getToken(true)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var sb strings.Builder
	sb.WriteString("https://tidal.com/v1/tracks/")
	sb.WriteString(id)
	sb.WriteString("/playbackinfo?audioquality=")
	sb.WriteString(c.Query("quality", "HI_RES_LOSSLESS"))
	sb.WriteString("&playbackmode=STREAM&assetpresentation=FULL")

	data, statusCode, err := a.makeRequest(sb.String(), token)
	if err != nil || statusCode != fasthttp.StatusOK {
		return c.Status(statusCode).JSON(fiber.Map{"error": "track not found or quality unavailable"})
	}
	var result struct {
		Manifest         string `json:"manifest"`
		ManifestMimeType string `json:"manifestMimeType"`
	}
	if err := fastJSON.Unmarshal(data, &result); err != nil || result.Manifest == "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "manifest not found"})
	}
	decoded, err := base64.StdEncoding.DecodeString(result.Manifest)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "manifest decode failed"})
	}
	c.Set(fiber.HeaderContentType, result.ManifestMimeType)
	return c.Send(decoded)
}

func (a *App) trackHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	quality := c.Query("quality", "LOSSLESS")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}
	if quality == "HI_RES_LOSSLESS" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "HI_RES_LOSSLESS not supported on this endpoint. Use /dash/ endpoint instead which returns MPEG-DASH."})
	}
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var wg sync.WaitGroup
	var infoData, trackData []byte
	var infoErr, trackErr error
	var infoStatusCode, trackStatusCode int
	wg.Add(2)

	go func() {
		defer wg.Done()
		var sb strings.Builder
		sb.WriteString("https://api.tidal.com/v1/tracks/")
		sb.WriteString(id)
		sb.WriteString("/?countryCode=US")
		infoData, infoStatusCode, infoErr = a.makeRequest(sb.String(), token)
	}()
	go func() {
		defer wg.Done()
		var sb strings.Builder
		sb.WriteString("https://api.tidal.com/v1/tracks/")
		sb.WriteString(id)
		sb.WriteString("/playbackinfopostpaywall/v4?audioquality=")
		sb.WriteString(quality)
		sb.WriteString("&playbackmode=STREAM&assetpresentation=FULL")
		trackData, trackStatusCode, trackErr = a.makeRequest(sb.String(), token)
	}()
	wg.Wait()

	if infoErr != nil || trackErr != nil || infoStatusCode != fasthttp.StatusOK || trackStatusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "track not found or quality unavailable"})
	}

	var pbm playbackInfoManifest
	if err := fastJSON.Unmarshal(trackData, &pbm); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to parse manifest"})
	}

	decoded, _ := base64.StdEncoding.DecodeString(pbm.Manifest)
	var mu manifestURL
	fastJSON.Unmarshal(decoded, &mu)
	audioURL := ""
	if len(mu.URLs) > 0 {
		audioURL = mu.URLs[0]
	}

	return c.JSON([]interface{}{
		json.RawMessage(infoData),
		json.RawMessage(trackData),
		fiber.Map{"OriginalTrackUrl": audioURL},
	})
}

func (a *App) lyricsHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}
	token, _ := a.getToken(false)
	var sb strings.Builder
	sb.WriteString("https://api.tidal.com/v1/tracks/")
	sb.WriteString(id)
	sb.WriteString("/lyrics?countryCode=US&locale=en_US&deviceType=BROWSER")

	data, statusCode, err := a.makeRequest(sb.String(), token)
	if err != nil || statusCode != fasthttp.StatusOK {
		return c.Status(statusCode).JSON(fiber.Map{"error": "failed to fetch lyrics"})
	}

	return c.JSON([]interface{}{
		json.RawMessage(data),
	})
}

func (a *App) songHandler(c *fiber.Ctx) error {
	q := c.Query("q")
	if q == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "q parameter required"})
	}
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var sb strings.Builder
	sb.WriteString("https://api.tidal.com/v1/search/tracks?countryCode=US&query=")
	sb.WriteString(url.QueryEscape(q))
	sb.WriteString("&limit=1")

	searchData, statusCode, err := a.makeRequest(sb.String(), token)
	if err != nil || statusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "search failed"})
	}

	var searchResult struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := fastJSON.Unmarshal(searchData, &searchResult); err != nil || len(searchResult.Items) == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "no results found"})
	}

	firstItem := searchResult.Items[0]

	var idExtractor struct {
		ID float64 `json:"id"`
	}
	if err := fastJSON.Unmarshal(firstItem, &idExtractor); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "invalid track ID in search result"})
	}

	sb.Reset()
	sb.WriteString("https://api.tidal.com/v1/tracks/")
	sb.WriteString(fmt.Sprintf("%.0f", idExtractor.ID))
	sb.WriteString("/playbackinfopostpaywall/v4?audioquality=")
	sb.WriteString(c.Query("quality", "LOSSLESS"))
	sb.WriteString("&playbackmode=STREAM&assetpresentation=FULL")

	trackData, trackStatusCode, err := a.makeRequest(sb.String(), token)
	if err != nil || trackStatusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "playback info not found"})
	}

	var pbm playbackInfoManifest
	fastJSON.Unmarshal(trackData, &pbm)
	decoded, _ := base64.StdEncoding.DecodeString(pbm.Manifest)

	var mu manifestURL
	fastJSON.Unmarshal(decoded, &mu)
	audioURL := ""
	if len(mu.URLs) > 0 {
		audioURL = mu.URLs[0]
	}

	return c.JSON([]interface{}{
		json.RawMessage(firstItem),
		json.RawMessage(trackData),
		fiber.Map{"OriginalTrackUrl": audioURL},
	})
}

func (a *App) searchHandler(c *fiber.Ctx) error {
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var sb strings.Builder
	var wrapInArray bool
	switch {
	case c.Query("s") != "":
		sb.WriteString("https://api.tidal.com/v1/search/tracks?query=")
		sb.WriteString(url.QueryEscape(c.Query("s")))
	case c.Query("a") != "":
		sb.WriteString("https://api.tidal.com/v1/search/top-hits?query=")
		sb.WriteString(url.QueryEscape(c.Query("a")))
		sb.WriteString("&types=ARTISTS,TRACKS")
		wrapInArray = true
	case c.Query("al") != "":
		sb.WriteString("https://api.tidal.com/v1/search/top-hits?query=")
		sb.WriteString(url.QueryEscape(c.Query("al")))
		sb.WriteString("&types=ALBUMS")
	case c.Query("v") != "":
		sb.WriteString("https://api.tidal.com/v1/search/top-hits?query=")
		sb.WriteString(url.QueryEscape(c.Query("v")))
		sb.WriteString("&types=VIDEOS")
	case c.Query("p") != "":
		sb.WriteString("https://api.tidal.com/v1/search/top-hits?query=")
		sb.WriteString(url.QueryEscape(c.Query("p")))
		sb.WriteString("&types=PLAYLISTS")
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "search parameter required (s, a, al, v, or p)"})
	}
	fmt.Fprintf(&sb, "&limit=%d&offset=%d&countryCode=US", c.QueryInt("li", 25), c.QueryInt("o", 0))

	data, statusCode, err := a.makeRequest(sb.String(), token)
	if err != nil || statusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "search failed"})
	}

	if wrapInArray {
		return c.JSON([]interface{}{json.RawMessage(data)})
	}

	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Send(data)
}

func (a *App) albumHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var wg sync.WaitGroup
	var albumData, itemsData []byte
	var albumErr, itemsErr error
	var albumStatusCode, itemsStatusCode int
	wg.Add(2)

	go func() {
		defer wg.Done()
		var sb strings.Builder
		sb.WriteString("https://api.tidal.com/v1/albums/")
		sb.WriteString(id)
		sb.WriteString("/?countryCode=US")
		albumData, albumStatusCode, albumErr = a.makeRequest(sb.String(), token)
	}()
	go func() {
		defer wg.Done()
		var sb strings.Builder
		sb.WriteString("https://api.tidal.com/v1/albums/")
		sb.WriteString(id)
		sb.WriteString("/items?limit=100&countryCode=US")
		itemsData, itemsStatusCode, itemsErr = a.makeRequest(sb.String(), token)
	}()
	wg.Wait()

	if albumErr != nil || itemsErr != nil || albumStatusCode != fasthttp.StatusOK || itemsStatusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "album or items not found"})
	}

	return c.JSON([]interface{}{
		json.RawMessage(albumData),
		json.RawMessage(itemsData),
	})
}

func (a *App) playlistHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var wg sync.WaitGroup
	var playlistData, itemsData []byte
	var playlistErr, itemsErr error
	var playlistStatusCode, itemsStatusCode int
	wg.Add(2)

	go func() {
		defer wg.Done()
		var sb strings.Builder
		sb.WriteString("https://api.tidal.com/v1/playlists/")
		sb.WriteString(id)
		sb.WriteString("?countryCode=US")
		playlistData, playlistStatusCode, playlistErr = a.makeRequest(sb.String(), token)
	}()
	go func() {
		defer wg.Done()
		var sb strings.Builder
		sb.WriteString("https://api.tidal.com/v1/playlists/")
		sb.WriteString(id)
		sb.WriteString("/items?countryCode=US&limit=100")
		itemsData, itemsStatusCode, itemsErr = a.makeRequest(sb.String(), token)
	}()
	wg.Wait()

	if playlistErr != nil || itemsErr != nil || playlistStatusCode != fasthttp.StatusOK || itemsStatusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "playlist or items not found"})
	}

	return c.JSON([]interface{}{
		json.RawMessage(playlistData),
		json.RawMessage(itemsData),
	})
}

type artistPageAlbums struct {
	Rows []struct {
		Modules []struct {
			PagedList struct {
				Items []struct {
					ID float64 `json:"id"`
				} `json:"items"`
			} `json:"pagedList"`
		} `json:"modules"`
	} `json:"rows"`
}

type albumPageTracks struct {
	Rows []struct {
		Modules []struct {
			PagedList struct {
				Items []struct {
					Item json.RawMessage `json:"item"`
				} `json:"items"`
			} `json:"pagedList"`
		} `json:"modules"`
	} `json:"rows"`
}

func (a *App) artistHandler(c *fiber.Ctx) error {
	id, f := c.Query("id"), c.Query("f")
	if id == "" && f == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id or f parameter required"})
	}
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var sb strings.Builder
	if id != "" {
		sb.WriteString("https://api.tidal.com/v1/artists/")
		sb.WriteString(id)
		sb.WriteString("?countryCode=US")
		data, statusCode, err := a.makeRequest(sb.String(), token)

		if err != nil || statusCode == fasthttp.StatusNotFound {
			sb.Reset()
			sb.WriteString("https://api.tidal.com/v1/pages/artist?artistId=")
			sb.WriteString(id)
			sb.WriteString("&countryCode=US&locale=en_US&deviceType=BROWSER")
			pageData, pageStatusCode, pageErr := a.makeRequest(sb.String(), token)
			if pageErr != nil || pageStatusCode != fasthttp.StatusOK {
				return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "artist not found"})
			}
			return c.JSON([]interface{}{json.RawMessage(pageData)})
		}

		var artistResult struct {
			ID      float64 `json:"id"`
			Name    string  `json:"name"`
			Picture string  `json:"picture"`
		}
		fastJSON.Unmarshal(data, &artistResult)

		sb.Reset()
		sb.WriteString("https://resources.tidal.com/images/")
		sb.WriteString(strings.ReplaceAll(artistResult.Picture, "-", "/"))
		basePath := sb.String()

		jsonData := []fiber.Map{{"id": int(artistResult.ID), "name": artistResult.Name, "750": basePath + "/750x750.jpg"}}
		return c.JSON([]interface{}{json.RawMessage(data), jsonData})
	}

	if f != "" {
		sb.WriteString("https://api.tidal.com/v1/pages/single-module-page/ae223310-a4c2-4568-a770-ffef70344441/4/a4f964ba-b52e-41e8-b25c-06cd70c1efad/2?artistId=")
		sb.WriteString(f)
		sb.WriteString("&countryCode=US&deviceType=BROWSER")
		albumData, statusCode, err := a.makeRequest(sb.String(), token)
		if err != nil || statusCode != fasthttp.StatusOK {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch artist albums"})
		}

		var albumsParsed artistPageAlbums
		fastJSON.Unmarshal(albumData, &albumsParsed)

		if len(albumsParsed.Rows) == 0 || len(albumsParsed.Rows[0].Modules) == 0 {
			return c.JSON([]interface{}{json.RawMessage(albumData)})
		}

		albumItems := albumsParsed.Rows[0].Modules[0].PagedList.Items
		allTracksSlices := make([][]json.RawMessage, len(albumItems))
		var wg sync.WaitGroup

		for i, item := range albumItems {
			wg.Add(1)
			go func(idx int, albumID float64) {
				defer wg.Done()
				var sbURL strings.Builder
				sbURL.WriteString("https://api.tidal.com/v1/pages/album?albumId=")
				sbURL.WriteString(fmt.Sprintf("%.0f", albumID))
				sbURL.WriteString("&countryCode=US&deviceType=BROWSER")

				albumInfoData, _, _ := a.makeRequest(sbURL.String(), token)
				var albumInfoParsed albumPageTracks
				fastJSON.Unmarshal(albumInfoData, &albumInfoParsed)

				if len(albumInfoParsed.Rows) > 1 && len(albumInfoParsed.Rows[1].Modules) > 0 {
					trackItems := albumInfoParsed.Rows[1].Modules[0].PagedList.Items
					tracks := make([]json.RawMessage, len(trackItems))
					for j, trackItem := range trackItems {
						tracks[j] = trackItem.Item
					}
					allTracksSlices[idx] = tracks
				}
			}(i, item.ID)
		}
		wg.Wait()

		var totalTracks int
		for _, s := range allTracksSlices {
			totalTracks += len(s)
		}
		allTracks := make([]json.RawMessage, 0, totalTracks)
		for _, s := range allTracksSlices {
			allTracks = append(allTracks, s...)
		}
		return c.JSON([]interface{}{json.RawMessage(albumData), allTracks})
	}
	return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid parameters"})
}

func (a *App) coverHandler(c *fiber.Ctx) error {
	id, q := c.Query("id"), c.Query("q")
	if id == "" && q == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id or q parameter required"})
	}
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var sb strings.Builder
	if id != "" {
		sb.WriteString("https://api.tidal.com/v1/tracks/")
		sb.WriteString(id)
		sb.WriteString("/?countryCode=US")
		data, _, err := a.makeRequest(sb.String(), token)
		if err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "track not found"})
		}
		var trackResult struct {
			Album struct {
				ID    float64 `json:"id"`
				Title string  `json:"title"`
				Cover string  `json:"cover"`
			} `json:"album"`
		}
		fastJSON.Unmarshal(data, &trackResult)

		sb.Reset()
		sb.WriteString("https://resources.tidal.com/images/")
		sb.WriteString(strings.ReplaceAll(trackResult.Album.Cover, "-", "/"))
		basePath := sb.String()

		jsonData := []fiber.Map{{"id": int(trackResult.Album.ID), "name": trackResult.Album.Title, "1280": basePath + "/1280x1280.jpg", "640": basePath + "/640x640.jpg", "80": basePath + "/80x80.jpg"}}
		return c.JSON(jsonData)
	}

	sb.WriteString("https://api.tidal.com/v1/search/tracks?countryCode=US&query=")
	sb.WriteString(url.QueryEscape(q))
	data, _, err := a.makeRequest(sb.String(), token)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "search failed"})
	}
	var searchResult struct {
		Items []struct {
			ID    float64 `json:"id"`
			Title string  `json:"title"`
			Album struct {
				Cover string `json:"cover"`
			} `json:"album"`
		} `json:"items"`
	}
	fastJSON.Unmarshal(data, &searchResult)
	items := searchResult.Items
	if len(items) > 10 {
		items = items[:10]
	}

	jsonData := make([]fiber.Map, 0, len(items))
	for _, item := range items {
		sb.Reset()
		sb.WriteString("https://resources.tidal.com/images/")
		sb.WriteString(strings.ReplaceAll(item.Album.Cover, "-", "/"))
		basePath := sb.String()
		jsonData = append(jsonData, fiber.Map{"id": int(item.ID), "name": item.Title, "1280": basePath + "/1280x1280.jpg", "640": basePath + "/640x640.jpg", "80": basePath + "/80x80.jpg"})
	}
	return c.JSON(jsonData)
}

func (a *App) homeHandler(c *fiber.Ctx) error {
	token, err := a.getToken(false)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "token refresh failed"})
	}

	var sb strings.Builder
	sb.WriteString("https://api.tidal.com/v1/pages/home?countryCode=")
	sb.WriteString(strings.ToUpper(c.Query("country", "US")))
	sb.WriteString("&deviceType=BROWSER")
	data, statusCode, err := a.makeRequest(sb.String(), token)
	if err != nil || statusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to fetch home"})
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Send(data)
}

func (a *App) mixHandler(c *fiber.Ctx) error {
	id := c.Query("id")
	if id == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "id parameter required"})
	}
	var sb strings.Builder
	sb.WriteString("https://api.tidal.com/v1/mixes/")
	sb.WriteString(id)
	sb.WriteString("/items?countryCode=")
	sb.WriteString(strings.ToUpper(c.Query("country", "US")))

	headers := map[string]string{"x-tidal-token": a.config.ClientID}
	data, statusCode, err := a.makeRequestWithHeader(sb.String(), headers)
	if err != nil || statusCode != fasthttp.StatusOK {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "request failed"})
	}
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Send(data)
}

func main() {
	app := newApp()

	fiberApp := fiber.New(fiber.Config{
		Prefork:       false,
		CaseSensitive: true,
		ServerHeader:  "HiFi-Go",
		AppName:       "HiFi-RestAPI v1.0",
		JSONEncoder:   fastJSON.Marshal,
		JSONDecoder:   fastJSON.Unmarshal,
	})
	fiberApp.Use(
		recover.New(),
		logger.New(logger.Config{Format: "${time} | ${status} | ${latency} | ${method} ${path}\n", TimeFormat: "15:04:05"}),
		compress.New(),
		cors.New(cors.Config{AllowOrigins: "*", AllowMethods: "GET"}),
	)

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
		log.Println("Shutting down...")
		_ = fiberApp.Shutdown()
	}()

	log.Printf("Server starting on port %s", app.config.Port)
	if err := fiberApp.Listen(":" + app.config.Port); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
