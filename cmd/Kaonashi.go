package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
)

// Config struct to hold configuration values
type Config struct {
	TelegramBotToken string `json:"telegram_bot_token"`
	ChatID           int64  `json:"chat_id"`
	HIBPAPIKey       string `json:"hibp_api_key"`
	VTAPIKey         string `json:"vt_api_key"`
}

// VirusTotalResponse represents the structure of the response from VirusTotal
type VirusTotalResponse struct {
	Data struct {
		ID         string `json:"id"`
		Type       string `json:"type"`
		Attributes struct {
			LastAnalysisResults map[string]interface{} `json:"last_analysis_results"`
		} `json:"attributes"`
	} `json:"data"`
}

type Breach struct {
	Name        string `json:"Name"`
	Domain      string `json:"Domain"`
	BreachDate  string `json:"BreachDate"`
	Title       string `json:"Title"`
	Description string `json:"Description"`
}

func loadConfig(filename string) (Config, error) {
	var config Config

	configFile, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("Error reading config file: %v", err)
	}

	log.Printf("Config File Content: %s", string(configFile))

	err = json.Unmarshal(configFile, &config)
	if err != nil {
		return config, fmt.Errorf("Error unmarshalling config file: %v", err)
	}

	return config, nil
}

func checkPwned(email string, hibpAPIKey string) (string, error) {
	apiURL := fmt.Sprintf("https://haveibeenpwned.com/api/v3/breachedaccount/%s?truncateResponse=false", email)

	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("Error creating HTTP request: %v", err)
	}

	req.Header.Set("hibp-api-key", hibpAPIKey)

	log.Printf("API Request URL: %s", apiURL)

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error sending HTTP request: %v", err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("Error reading response body: %v", err)
	}

	log.Printf("Response Code: %d", response.StatusCode)
	log.Printf("Response Body: %s", string(body))

	if response.StatusCode == http.StatusOK {
		var breaches []Breach
		err := json.Unmarshal(body, &breaches)
		if err != nil {
			return "", fmt.Errorf("Error parsing JSON response: %v", err)
		}

		if len(breaches) == 0 {
			return "Good news! Your email has not been pwned.", nil
		}

		// Build the response with essential breach information
		var responseBuilder strings.Builder
		responseBuilder.WriteString("Your email has been pwned in the following breaches:\n\n")

		for _, breach := range breaches {
			// Remove the description completely
			responseBuilder.WriteString(fmt.Sprintf("Name: %s\nDomain: %s\nBreach Date: %s\nTitle: %s\n\n",
				breach.Name, breach.Domain, breach.BreachDate, breach.Title))
		}

		return responseBuilder.String(), nil
	} else if response.StatusCode == http.StatusNotFound {
		return "Good news! Your email has not been pwned.", nil
	} else {
		log.Printf("Non-OK Response Code: %d", response.StatusCode)
		return "", fmt.Errorf("Non-OK response code: %d - %s", response.StatusCode, string(body))
	}
}

func checkMalware(hash string, vtAPIKey string) (string, error) {
	apiURL := fmt.Sprintf("https://www.virustotal.com/api/v3/files/%s", hash)

	client := &http.Client{}
	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return "", fmt.Errorf("Error creating HTTP request: %v", err)
	}

	req.Header.Set("x-apikey", vtAPIKey)

	log.Printf("API Request URL: %s", apiURL)

	response, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error sending HTTP request: %v", err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("Error reading response body: %v", err)
	}

	log.Printf("Response Code: %d", response.StatusCode)
	log.Printf("Response Body: %s", string(body))

	if response.StatusCode == http.StatusOK {
		var vtResponse VirusTotalResponse
		err := json.Unmarshal(body, &vtResponse)
		if err != nil {
			return "", fmt.Errorf("Error parsing JSON response: %v", err)
		}

		lastAnalysisResults := vtResponse.Data.Attributes.LastAnalysisResults
		if len(lastAnalysisResults) == 0 {
			return "No analysis results available.", nil
		}

		// Build a response with the relevant information
		var responseBuilder strings.Builder
		responseBuilder.WriteString("Scan results:\n")

		for engine, result := range lastAnalysisResults {
			responseBuilder.WriteString(fmt.Sprintf("Engine: %s, Result: %+v\n", engine, result))
		}

		return "Positive Found: This is a malware 💀", nil
	} else {
		return "", fmt.Errorf("Non-OK response code: %d", response.StatusCode)
	}
}

func sendMessage(bot *tgbotapi.BotAPI, chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	bot.Send(msg)
}

func askForConfigFile(bot *tgbotapi.BotAPI, chatID int64) {
	msg := tgbotapi.NewMessage(chatID, "Please send your configuration file (config.json).")
	bot.Send(msg)
}

func updateConfigFile(configFileContent string) error {
	err := ioutil.WriteFile("config.json", []byte(configFileContent), 0644)
	if err != nil {
		return fmt.Errorf("Error updating config file: %v", err)
	}
	return nil
}
func askForEmail(bot *tgbotapi.BotAPI, chatID int64) {
	msg := tgbotapi.NewMessage(chatID, "Please enter your email address:")
	msg.ReplyMarkup = tgbotapi.ForceReply{ForceReply: true, Selective: true}
	bot.Send(msg)
}

func askForFileHash(bot *tgbotapi.BotAPI, chatID int64) {
	msg := tgbotapi.NewMessage(chatID, "Please enter the hash of the file:")
	msg.ReplyMarkup = tgbotapi.ForceReply{ForceReply: true, Selective: true}
	bot.Send(msg)
}
func main() {
	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	bot, err := tgbotapi.NewBotAPI(config.TelegramBotToken)
	if err != nil {
		log.Fatalf("Error initializing Telegram bot: %v", err)
	}

	log.Printf("Authorized on account %s", bot.Self.UserName)

	// Send a default message when the bot starts
	defaultMessage := "Chomp, chomp... Kaonashi is hungry, upload config.json with API Key!"
	sendMessage(bot, config.ChatID, defaultMessage)

	// Ask for the configuration file
	askForConfigFile(bot, config.ChatID)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates, err := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message == nil {
			continue
		}

		log.Printf("Received message: %s", update.Message.Text)
		switch {
		case strings.HasPrefix(update.Message.Text, "/checkpwned"):
			askForEmail(bot, update.Message.Chat.ID)
		case strings.HasPrefix(update.Message.Text, "/checkmalware"):
			askForFileHash(bot, update.Message.Chat.ID)
		}

		if update.Message.ReplyToMessage != nil && strings.HasPrefix(update.Message.ReplyToMessage.Text, "Please enter your email address:") {
			emailInput := strings.TrimSpace(update.Message.Text)
			log.Printf("Email input: %s", emailInput)

			result, err := checkPwned(emailInput, config.HIBPAPIKey)
			if err != nil {
				log.Printf("Error checking for pwned status: %v", err)
				sendMessage(bot, update.Message.Chat.ID, "An error occurred while checking the pwned status.")
				continue
			}

			log.Printf("Sending response: %s", result)
			sendMessage(bot, update.Message.Chat.ID, result)
		} else if update.Message.ReplyToMessage != nil && update.Message.ReplyToMessage.Text == "Please enter the hash of the file:" {
			hashInput := strings.TrimSpace(update.Message.Text)
			log.Printf("File hash input: %s", hashInput)

			result, err := checkMalware(hashInput, config.VTAPIKey)
			if err != nil {
				log.Printf("Error checking for malware: %v", err)
				sendMessage(bot, update.Message.Chat.ID, "An error occurred while checking for malware.")
				continue
			}

			log.Printf("Sending response: %s", result)
			sendMessage(bot, update.Message.Chat.ID, result)
		}

		if update.Message.Document != nil {
			documentID := update.Message.Document.FileID
			fileConfig := tgbotapi.FileConfig{
				FileID: documentID,
			}

			file, err := bot.GetFile(fileConfig)
			if err != nil {
				log.Printf("Error getting file: %v", err)
				sendMessage(bot, config.ChatID, "An error occurred while getting the file.")
				continue
			}

			// Move the code inside this block
			fileURL := fmt.Sprintf("https://api.telegram.org/file/bot%s/%s", config.TelegramBotToken, file.FilePath)
			fileContent, err := downloadFile(fileURL)

			err = updateConfigFile(string(fileContent))
			if err != nil {
				log.Printf("Error updating config file: %v", err)
				sendMessage(bot, config.ChatID, "An error occurred while updating the config file.")
				continue
			}

			log.Printf("Config file updated successfully.")
			sendMessage(bot, config.ChatID, "Gnom...Gnom...Config file eaten successfully. /checkmalware or /checkpwned")
		}
	}
}

func downloadFile(url string) ([]byte, error) {
	response, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("Error downloading file: %v", err)
	}
	defer response.Body.Close()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, fmt.Errorf("Error reading response body: %v", err)
	}

	return body, nil
}
