package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/fatih/color"
	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

type Listener struct {
	ID           int
	Name         string
	Port         string
	IP           string
	Running      bool
	Time         string
	AesKey       string
	IV           string
	XorKey       string
	Protocol     string
	UserAgent    string
	ServerHeader string
	HTML404Path  string
	SSLCertPath  string
	SSLKeyPath   string
}

type Agent struct {
	ID         int
	Name       string
	ListenerID int // Foreign key
	ExternalIP string
	InternalIP string
	Time       string
	Hostname   string
	Token      string
	Username   string
	OS         string
	Active     bool
	Sleep      int
	Jitter     int
}

type Task struct {
	ID         int
	AgentID    int // Foreign key
	Command    string
	Arguments  []string
	Timeout    int
	Active     bool
	Success    bool
	InQueue    bool
	TimedOut   bool
	CreateTime string
	EndTime    string
	Result     string
}

func init() {
	var err error
	db, err = sql.Open("sqlite3", "./master.db")
	if err != nil {
		log.Fatal(err)
	}
	createTables()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func printColorized(format string, colorizer *color.Color, a ...interface{}) {
	colorizer.PrintfFunc()(format, a...)
}

func createTables() {
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS listener (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		port TEXT,
		ip TEXT,
		running BOOLEAN,
		time TEXT,
		aes_key TEXT,
		iv TEXT,
		xor_key TEXT,
		protocol TEXT,
		user_agent TEXT,
		server_header TEXT,
		html_404_path TEXT,
		ssl_cert_path TEXT,
		ssl_key_path TEXT
		);`)
	if err != nil {
		log.Fatal("Error in creating listener table:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS agent (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT,
		listener_id INTEGER,
		external_ip TEXT,
		internal_ip TEXT,
		time TEXT,
		hostname TEXT,
		token TEXT,
		username TEXT,
		os TEXT,
		active BOOLEAN,
		sleep INTEGER,
		jitter INTEGER,
		FOREIGN KEY (listener_id) REFERENCES listener(id)
		);`)
	if err != nil {
		log.Fatal("Error in creating agent table:", err)
	}

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS task (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		agent_id INTEGER,
		command TEXT,
		arguments TEXT,
		timeout INTEGER,
		active BOOLEAN,
		success BOOLEAN,
		in_queue BOOLEAN,
		timed_out BOOLEAN,
		create_time TEXT,
		end_time TEXT,
		result TEXT,
		FOREIGN KEY (agent_id) REFERENCES agent(id)
		);`)
	if err != nil {
		log.Fatal("Error in creating task table:", err)
	}
}

func InsertListener(listener *Listener) error {
	result, err := db.Exec("INSERT INTO listener(name, port, ip, running, time, aes_key, iv, xor_key, protocol, user_agent, server_header, html_404_path, ssl_cert_path, ssl_key_path) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		listener.Name,
		listener.Port,
		listener.IP,
		listener.Running,
		listener.Time,
		listener.AesKey,
		listener.IV,
		listener.XorKey,
		listener.Protocol,
		listener.UserAgent,
		listener.ServerHeader,
		listener.HTML404Path,
		listener.SSLCertPath,
		listener.SSLKeyPath)
	if err != nil {
		return fmt.Errorf("error in inserting listener: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("error in getting last insert ID for listener: %w", err)
	}
	listener.ID = int(id)
	return nil
}

func InsertAgent(agent *Agent) error {
	result, err := db.Exec("INSERT INTO agent(name, listener_id, external_ip, internal_ip, time, hostname, token, username, os, active, sleep, jitter) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		agent.Name,
		agent.ListenerID,
		agent.ExternalIP,
		agent.InternalIP,
		agent.Time,
		agent.Hostname,
		agent.Token,
		agent.Username,
		agent.OS,
		agent.Active,
		agent.Sleep,
		agent.Jitter)
	if err != nil {
		return fmt.Errorf("error in inserting agent: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("error in getting last insert ID for agent: %w", err)
	}
	agent.ID = int(id)
	return nil
}

func InsertTask(task *Task) error {
	arguments, err := serializeArguments(task.Arguments)
	if err != nil {
		return fmt.Errorf("error in serializing arguments: %w", err)
	}
	result, err := db.Exec("INSERT INTO task(agent_id, command, arguments, timeout, active, success, in_queue, timed_out, create_time, end_time, result) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		task.AgentID,
		task.Command,
		arguments,
		task.Timeout,
		task.Active,
		task.Success,
		task.InQueue,
		task.TimedOut,
		task.CreateTime,
		task.EndTime,
		task.Result)
	if err != nil {
		return fmt.Errorf("error in inserting task: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return fmt.Errorf("error in getting last insert ID for task: %w", err)
	}
	task.ID = int(id)
	return nil
}

// GetListenerByID fetches the Listener associated with a given ID.
func GetListenerByID(id int) (Listener, error) {
	var listener Listener

	query := "SELECT id, name, port, ip, running, time, aes_key, iv, xor_key, protocol, user_agent, server_header, html_404_path, ssl_cert_path, ssl_key_path FROM listener WHERE id = ?"
	err := db.QueryRow(query, id).Scan(&listener.ID, &listener.Name, &listener.Port, &listener.IP, &listener.Running, &listener.Time, &listener.AesKey, &listener.IV, &listener.XorKey, &listener.Protocol, &listener.UserAgent, &listener.ServerHeader, &listener.HTML404Path, &listener.SSLCertPath, &listener.SSLKeyPath)
	if err != nil {
		if err == sql.ErrNoRows {
			return Listener{}, nil
		}
		return Listener{}, fmt.Errorf("Error fetching the listener by ID: %v", err)
	}
	return listener, nil
}

// ListListeners lists all the listeners and returns them as a slice.
func ListListeners() ([]Listener, error) {
	var listeners []Listener

	// Initial max widths definition based on header lengths
	maxWidths := map[string]int{
		"ID": 2, "NAME": 4, "PORT": 4, "IP": 2, "RUNNING": 7, "TIME": 4,
		"AES_KEY": 7, "IV": 2, "XOR_KEY": 7, "PROTOCOL": 8, "USER_AGENT": 10,
		"SERVER_HEADER": 13, "HTML_404_PATH": 13, "SSL_CERT_PATH": 13,
		"SSL_KEY_PATH": 12,
	}

	// First pass to calculate max widths and read data
	rows, err := db.Query("SELECT * FROM listener")
	if err != nil {
		return nil, fmt.Errorf("Error querying the listener table: %v", err)
	}

	for rows.Next() {
		var listener Listener
		err := rows.Scan(&listener.ID, &listener.Name, &listener.Port, &listener.IP, &listener.Running, &listener.Time, &listener.AesKey, &listener.IV, &listener.XorKey, &listener.Protocol, &listener.UserAgent, &listener.ServerHeader, &listener.HTML404Path, &listener.SSLCertPath, &listener.SSLKeyPath)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("Error scanning row: %v", err)
		}

		// Update maxWidths based on the length of the data
		maxWidths["ID"] = max(maxWidths["ID"], len(fmt.Sprintf("%d", listener.ID)))
		maxWidths["NAME"] = max(maxWidths["NAME"], len(listener.Name))
		maxWidths["PORT"] = max(maxWidths["PORT"], len(listener.Port))
		maxWidths["IP"] = max(maxWidths["IP"], len(listener.IP))
		maxWidths["RUNNING"] = max(maxWidths["RUNNING"], len(fmt.Sprintf("%t", listener.Running)))
		maxWidths["TIME"] = max(maxWidths["TIME"], len(listener.Time))
		maxWidths["AES_KEY"] = max(maxWidths["AES_KEY"], len(listener.AesKey))
		maxWidths["IV"] = max(maxWidths["IV"], len(listener.IV))
		maxWidths["XOR_KEY"] = max(maxWidths["XOR_KEY"], len(listener.XorKey))
		maxWidths["PROTOCOL"] = max(maxWidths["PROTOCOL"], len(listener.Protocol))
		maxWidths["USER_AGENT"] = max(maxWidths["USER_AGENT"], len(listener.UserAgent))
		maxWidths["SERVER_HEADER"] = max(maxWidths["SERVER_HEADER"], len(listener.ServerHeader))
		maxWidths["HTML_404_PATH"] = max(maxWidths["HTML_404_PATH"], len(listener.HTML404Path))
		maxWidths["SSL_CERT_PATH"] = max(maxWidths["SSL_CERT_PATH"], len(listener.SSLCertPath))
		maxWidths["SSL_KEY_PATH"] = max(maxWidths["SSL_KEY_PATH"], len(listener.SSLKeyPath))

		listeners = append(listeners, listener)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("Error during row iteration: %v", err)
	}
	rows.Close() // Close the rows before the second pass

	// Define colors for each column
	columnColors := []*color.Color{
		color.New(color.FgHiRed),     // ID
		color.New(color.FgHiGreen),   // NAME
		color.New(color.FgHiYellow),  // PORT
		color.New(color.FgHiBlue),    // IP
		color.New(color.FgHiMagenta), // RUNNING
		color.New(color.FgHiCyan),    // TIME
		color.New(color.FgHiWhite),   // AES_KEY
		color.New(color.FgHiRed),     // IV
		color.New(color.FgHiGreen),   // XOR_KEY
		color.New(color.FgHiYellow),  // PROTOCOL
		color.New(color.FgHiBlue),    // USER_AGENT
		color.New(color.FgHiMagenta), // SERVER_HEADER
		color.New(color.FgHiCyan),    // HTML_404_PATH
		color.New(color.FgHiWhite),   // SSL_CERT_PATH
		color.New(color.FgHiRed),     // SSL_KEY_PATH
	}

	// Print headers with colors
	headers := []string{"ID", "NAME", "PORT", "IP", "RUNNING", "TIME", "AES_KEY", "IV", "XOR_KEY", "PROTOCOL", "USER_AGENT", "SERVER_HEADER", "HTML_404_PATH", "SSL_CERT_PATH", "SSL_KEY_PATH"}
	for i, header := range headers {
		if i < len(headers)-1 { // If it's not the last header, print with the separator
			columnColors[i].PrintfFunc()("%-*s | ", maxWidths[header], header)
		} else { // If it's the last header, print without the separator
			columnColors[i].PrintfFunc()("%-*s", maxWidths[header], header)
		}
	}
	fmt.Println() // Newline after headers

	// Second pass to print the data with the correct widths
	for _, listener := range listeners {
		columnColors[0].PrintfFunc()("%-*d | ", maxWidths["ID"], listener.ID)
		columnColors[1].PrintfFunc()("%-*s | ", maxWidths["NAME"], listener.Name)
		columnColors[2].PrintfFunc()("%-*s | ", maxWidths["PORT"], listener.Port)
		columnColors[3].PrintfFunc()("%-*s | ", maxWidths["IP"], listener.IP)
		columnColors[4].PrintfFunc()("%-*t | ", maxWidths["RUNNING"], listener.Running)
		columnColors[5].PrintfFunc()("%-*s | ", maxWidths["TIME"], listener.Time)
		columnColors[6].PrintfFunc()("%-*s | ", maxWidths["AES_KEY"], listener.AesKey)
		columnColors[7].PrintfFunc()("%-*s | ", maxWidths["IV"], listener.IV)
		columnColors[8].PrintfFunc()("%-*s | ", maxWidths["XOR_KEY"], listener.XorKey)
		columnColors[9].PrintfFunc()("%-*s | ", maxWidths["PROTOCOL"], listener.Protocol)
		columnColors[10].PrintfFunc()("%-*s | ", maxWidths["USER_AGENT"], listener.UserAgent)
		columnColors[11].PrintfFunc()("%-*s | ", maxWidths["SERVER_HEADER"], listener.ServerHeader)
		columnColors[12].PrintfFunc()("%-*s | ", maxWidths["HTML_404_PATH"], listener.HTML404Path)
		columnColors[13].PrintfFunc()("%-*s | ", maxWidths["SSL_CERT_PATH"], listener.SSLCertPath)
		columnColors[14].PrintfFunc()("%-*s\n", maxWidths["SSL_KEY_PATH"], listener.SSLKeyPath)
	}

	return listeners, nil
}

// UpdateListener updates an existing listener in the database.
func UpdateListener(listener *Listener) error {
	// SQL statement includes all fields of the Listener struct.
	stmt, err := db.Prepare(`
		UPDATE listener 
		SET name = ?, port = ?, ip = ?, running = ?, time = ?, aes_key = ?, iv = ?, xor_key = ?, protocol = ?, user_agent = ?, server_header = ?, html_404_path = ?, ssl_cert_path = ?, ssl_key_path = ?
		WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("error preparing SQL statement: %v", err)
	}
	defer stmt.Close()

	// Executing the statement with all fields of the Listener struct.
	_, err = stmt.Exec(listener.Name, listener.Port, listener.IP, listener.Running, listener.Time, listener.AesKey, listener.IV, listener.XorKey, listener.ID, listener.Protocol, listener.UserAgent, listener.ServerHeader, listener.HTML404Path, listener.SSLCertPath, listener.SSLKeyPath)
	if err != nil {
		return fmt.Errorf("error updating listener: %v", err)
	}

	return nil
}

// DeleteListenerByID removes a listener from the listener table by its ID.
func DeleteListenerByID(id int) error {
	_, err := db.Exec("DELETE FROM listener WHERE id = ?", id)
	if err != nil {
		return fmt.Errorf("Error deleting listener by ID: %v", err)
	}

	return nil
}

// DeleteAllListeners removes all listeners from the listener table.
func DeleteAllListeners() error {
	_, err := db.Exec("DELETE FROM listener")
	if err != nil {
		return fmt.Errorf("Error deleting all listeners: %v", err)
	}

	return nil
}

// ShutdownListeners sets the 'running' field of all listeners to false.
func ShutdownListeners() error {
	stmt, err := db.Prepare("UPDATE listener SET running = ?")
	if err != nil {
		return fmt.Errorf("error preparing SQL statement: %v", err)
	}
	defer stmt.Close()

	_, err = stmt.Exec(false)
	if err != nil {
		return fmt.Errorf("error updating listeners during shutdown: %v", err)
	}

	return nil
}

// GetAgentByID fetches the Agent associated with a given ID.
func GetAgentByID(id int) (Agent, error) {
	var agent Agent

	query := "SELECT id, name, listener_id, external_ip, internal_ip, time, hostname, token, username, os, active, sleep, jitter FROM agent WHERE id = ?"
	err := db.QueryRow(query, id).Scan(&agent.ID, &agent.Name, &agent.ListenerID, &agent.ExternalIP, &agent.InternalIP, &agent.Time, &agent.Hostname, &agent.Token, &agent.Username, &agent.OS, &agent.Active, &agent.Sleep, &agent.Jitter)
	if err != nil {
		if err == sql.ErrNoRows {
			return Agent{}, nil // No rows could be considered as not an error depending on your use-case.
		}
		return Agent{}, fmt.Errorf("Error fetching the agent by ID: %v", err)
	}

	return agent, nil
}

// calculateHumanReadableTime calculates time duration in human-readable format.
func calculateHumanReadableTime(timeSince time.Duration) string {
	days := timeSince.Hours() / 24
	if days >= 365 {
		return fmt.Sprintf("%.0f years, %.0fh%.0fm%.0fs", days/365, int(timeSince.Hours())%24, int(timeSince.Minutes())%60, int(timeSince.Seconds())%60)
	} else if days >= 30 {
		return fmt.Sprintf("%.0f months, %.0fh%.0fm%.0fs", days/30, int(timeSince.Hours())%24, int(timeSince.Minutes())%60, int(timeSince.Seconds())%60)
	} else if days >= 1 {
		return fmt.Sprintf("%.0f days, %.0fh%.0fm%.0fs", days, int(timeSince.Hours())%24, int(timeSince.Minutes())%60, int(timeSince.Seconds())%60)
	} else {
		return fmt.Sprintf("%.0fh%.0fm%.0fs", int(timeSince.Hours()), int(timeSince.Minutes())%60, int(timeSince.Seconds())%60)
	}
}

// GetAgentCheckinByID gets the last check-in time for an agent by ID.
func GetAgentCheckinByID(agentID int) (string, error) {
	var lastCheckin time.Time

	err := db.QueryRow("SELECT time FROM agent WHERE id = ?", agentID).Scan(&lastCheckin)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil // No rows could be considered as not an error depending on your use-case.
		}
		return "", fmt.Errorf("Error fetching the last check-in time: %v", err)
	}

	timeSince := time.Since(lastCheckin)
	humanReadableTime := calculateHumanReadableTime(timeSince)
	return humanReadableTime, nil
}

// ListAgents lists all the agents and returns them as a slice.
func ListAgents() ([]Agent, error) {
	var agents []Agent

	// First pass to calculate max widths and read data
	rows, err := db.Query("SELECT id, name, listener_id, external_ip, internal_ip, time, hostname, token, username, os, active, sleep, jitter FROM agent")
	if err != nil {
		return nil, fmt.Errorf("Error querying the agents: %v", err)
	}

	// Initial max widths definition based on header lengths
	maxWidths := map[string]int{
		"ID":          2,
		"NAME":        4,
		"LISTENER_ID": 11,
		"EXTERNAL_IP": 11,
		"INTERNAL_IP": 11,
		"TIME":        4,
		"HOSTNAME":    8,
		"TOKEN":       5,
		"USERNAME":    8,
		"OS":          2,
		"ACTIVE":      6,
		"SLEEP":       5,
		"JITTER":      6,
	}

	for rows.Next() {
		var agent Agent
		err := rows.Scan(&agent.ID, &agent.Name, &agent.ListenerID, &agent.ExternalIP, &agent.InternalIP, &agent.Time, &agent.Hostname, &agent.Token, &agent.Username, &agent.OS, &agent.Active, &agent.Sleep, &agent.Jitter)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("Error scanning row: %v", err)
		}

		// Update maxWidths based on the length of the data
		maxWidths["ID"] = max(maxWidths["ID"], len(fmt.Sprintf("%d", agent.ID)))
		maxWidths["NAME"] = max(maxWidths["NAME"], len(agent.Name))
		maxWidths["LISTENER_ID"] = max(maxWidths["LISTENER_ID"], len(fmt.Sprintf("%d", agent.ListenerID)))
		maxWidths["EXTERNAL_IP"] = max(maxWidths["EXTERNAL_IP"], len(agent.ExternalIP))
		maxWidths["INTERNAL_IP"] = max(maxWidths["INTERNAL_IP"], len(agent.InternalIP))
		maxWidths["TIME"] = max(maxWidths["TIME"], len(agent.Time))
		maxWidths["HOSTNAME"] = max(maxWidths["HOSTNAME"], len(agent.Hostname))
		maxWidths["TOKEN"] = max(maxWidths["TOKEN"], len(agent.Token))
		maxWidths["USERNAME"] = max(maxWidths["USERNAME"], len(agent.Username))
		maxWidths["OS"] = max(maxWidths["OS"], len(agent.OS))
		maxWidths["ACTIVE"] = max(maxWidths["ACTIVE"], len(fmt.Sprintf("%t", agent.Active)))
		maxWidths["SLEEP"] = max(maxWidths["SLEEP"], len(fmt.Sprintf("%d", agent.Sleep)))
		maxWidths["JITTER"] = max(maxWidths["JITTER"], len(fmt.Sprintf("%d", agent.Jitter)))

		agents = append(agents, agent)
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("Error during row iteration: %v", err)
	}
	rows.Close() // Close the rows before printing

	// Define colors for each column
	columnColors := []*color.Color{
		color.New(color.FgHiRed),     // ID
		color.New(color.FgHiGreen),   // NAME
		color.New(color.FgHiYellow),  // LISTENER_ID
		color.New(color.FgHiBlue),    // EXTERNAL_IP
		color.New(color.FgHiMagenta), // INTERNAL_IP
		color.New(color.FgHiCyan),    // TIME
		color.New(color.FgHiWhite),   // HOSTNAME
		color.New(color.FgHiRed),     // TOKEN
		color.New(color.FgHiGreen),   // USERNAME
		color.New(color.FgHiYellow),  // OS
		color.New(color.FgHiBlue),    // ACTIVE
		color.New(color.FgHiMagenta), // SLEEP
		color.New(color.FgHiCyan),    // JITTER
	}

	// Print empty line before column headers
	fmt.Println()

	// Print headers with colors
	headers := []string{"ID", "NAME", "LISTENER_ID", "EXTERNAL_IP", "INTERNAL_IP", "TIME", "HOSTNAME", "TOKEN", "USERNAME", "OS", "ACTIVE", "SLEEP", "JITTER"}
	for i, header := range headers {
		if i < len(headers)-1 {
			columnColors[i].PrintfFunc()("%-*s | ", maxWidths[header], header)
		} else {
			columnColors[i].PrintfFunc()("%-*s", maxWidths[header], header)
		}
	}
	fmt.Println() // Newline after headers

	// Print the data with colors
	for _, agent := range agents {
		columnColors[0].PrintfFunc()("%-*d | ", maxWidths["ID"], agent.ID)
		columnColors[1].PrintfFunc()("%-*s | ", maxWidths["NAME"], agent.Name)
		columnColors[2].PrintfFunc()("%-*d | ", maxWidths["LISTENER_ID"], agent.ListenerID)
		columnColors[3].PrintfFunc()("%-*s | ", maxWidths["EXTERNAL_IP"], agent.ExternalIP)
		columnColors[4].PrintfFunc()("%-*s | ", maxWidths["INTERNAL_IP"], agent.InternalIP)
		columnColors[5].PrintfFunc()("%-*s | ", maxWidths["TIME"], agent.Time)
		columnColors[6].PrintfFunc()("%-*s | ", maxWidths["HOSTNAME"], agent.Hostname)
		columnColors[7].PrintfFunc()("%-*s | ", maxWidths["TOKEN"], agent.Token)
		columnColors[8].PrintfFunc()("%-*s | ", maxWidths["USERNAME"], agent.Username)
		columnColors[9].PrintfFunc()("%-*s | ", maxWidths["OS"], agent.OS)
		columnColors[10].PrintfFunc()("%-*t | ", maxWidths["ACTIVE"], agent.Active)
		columnColors[11].PrintfFunc()("%-*d | ", maxWidths["SLEEP"], agent.Sleep)
		columnColors[12].PrintfFunc()("%-*d\n", maxWidths["JITTER"], agent.Jitter)
	}

	if len(agents) != 0 {
		fmt.Println("> ")
	}

	return agents, nil
}

// DeleteAgentByID deletes an agent by its ID from the database.
func DeleteAgentByID(id int) error {
	_, err := db.Exec("DELETE FROM agent WHERE id = ?", id)
	if err != nil {
		log.Println("Error deleting the agent by ID:", err)
		return err
	}
	err = DeleteTasksByAgentID(id)
	if err != nil {
		log.Println("Error deleting tasks by agent ID:", err)
		return err
	}
	return nil
}

// DeleteAllAgents deletes all agents from the agent table.
func DeleteAllAgents() error {
	_, err := db.Exec("DELETE FROM agent")
	if err != nil {
		log.Println("Error deleting all agents:", err)
		return err
	}
	err = DeleteAllTasks()
	if err != nil {
		log.Println("Error deleting all tasks:", err)
		return err
	}
	return nil
}

// UpdateAgentCheckinByID updates the check-in time for an agent based on its ID.
func UpdateAgentCheckinByID(agentID int) error {
	currentTime := time.Now().Format("2006-01-02 15:04:05.999999")
	_, err := db.Exec("UPDATE agent SET time = ? WHERE id = ?", currentTime, agentID)
	if err != nil {
		log.Println("Error updating the check-in time for the agent:", err)
		return err
	}
	return nil
}

// serializeArguments converts a slice of strings into a JSON string.
func serializeArguments(args []string) (string, error) {
	jsonArgs, err := json.Marshal(args)
	if err != nil {
		return "", err
	}
	return string(jsonArgs), nil
}

// deserializeArguments converts a JSON string into a slice of strings.
func deserializeArguments(jsonArgs string) ([]string, error) {
	var args []string
	err := json.Unmarshal([]byte(jsonArgs), &args)
	if err != nil {
		return nil, err
	}
	return args, nil
}

// GetTasksForAgent retrieves all the tasks for a specific agent ID and optionally prints them.
func GetTasksForAgent(agentID int, printTasks bool, inQueue bool) ([]Task, error) {
	// First pass to calculate max widths and read data
	query := "SELECT id, agent_id, command, arguments, timeout, active, success, in_queue, timed_out, create_time, end_time, result FROM task WHERE agent_id = ?"
	rows, err := db.Query(query, agentID)
	if err != nil {
		return nil, fmt.Errorf("Error querying the tasks for agent: %v", err)
	}
	defer rows.Close()

	var tasks []Task
	var argsJSON string
	var inQueueSerializedArgs []string
	var notInQueueSerializedArgs []string

	// Initial max widths definition based on header lengths
	maxWidths := map[string]int{
		"ID":          2,
		"AGENT_ID":    8,
		"COMMAND":     7,
		"ARGUMENTS":   9,
		"TIMEOUT":     7,
		"ACTIVE":      6,
		"SUCCESS":     7,
		"IN_QUEUE":    8,
		"TIMED_OUT":   9,
		"CREATE_TIME": 11,
		"END_TIME":    8,
		"RESULT":      6,
	}

	for rows.Next() {
		var task Task
		err := rows.Scan(&task.ID, &task.AgentID, &task.Command, &argsJSON, &task.Timeout, &task.Active, &task.Success, &task.InQueue, &task.TimedOut, &task.CreateTime, &task.EndTime, &task.Result)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("Error scanning row: %v", err)
		}

		// Add the serialized arguments to appropriate the slice based on queue status
		if inQueue && task.InQueue {
			inQueueSerializedArgs = append(inQueueSerializedArgs, argsJSON)
		} else if !inQueue && !task.InQueue {
			notInQueueSerializedArgs = append(notInQueueSerializedArgs, argsJSON)
		}

		// Update maxWidths based on the length of the data
		maxWidths["ID"] = max(maxWidths["ID"], len(fmt.Sprintf("%d", task.ID)))
		maxWidths["AGENT_ID"] = max(maxWidths["AGENT_ID"], len(fmt.Sprintf("%d", task.AgentID)))
		maxWidths["COMMAND"] = max(maxWidths["COMMAND"], len(task.Command))
		if inQueue && task.InQueue {
			maxWidths["ARGUMENTS"] = max(maxWidths["ARGUMENTS"], len(argsJSON))
		} else if !inQueue && !task.InQueue {
			maxWidths["ARGUMENTS"] = max(maxWidths["ARGUMENTS"], len(argsJSON))
		}
		maxWidths["TIMEOUT"] = max(maxWidths["TIMEOUT"], len(fmt.Sprintf("%d", task.Timeout)))
		maxWidths["ACTIVE"] = max(maxWidths["ACTIVE"], len(fmt.Sprintf("%t", task.Active)))
		maxWidths["SUCCESS"] = max(maxWidths["SUCCESS"], len(fmt.Sprintf("%t", task.Success)))
		maxWidths["IN_QUEUE"] = max(maxWidths["IN_QUEUE"], len(fmt.Sprintf("%t", task.InQueue)))
		maxWidths["TIMED_OUT"] = max(maxWidths["TIMED_OUT"], len(fmt.Sprintf("%t", task.TimedOut)))
		maxWidths["CREATE_TIME"] = max(maxWidths["CREATE_TIME"], len(task.CreateTime))
		maxWidths["END_TIME"] = max(maxWidths["END_TIME"], len(task.EndTime))

		// Deserialize the arguments
		task.Arguments, err = deserializeArguments(argsJSON)
		if err != nil {
			rows.Close()
			return nil, fmt.Errorf("Error deserializing arguments: %v", err)
		}

		if inQueue && task.InQueue {
			tasks = append(tasks, task)
		} else if !inQueue && !task.InQueue {
			tasks = append(tasks, task)
		}
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("Error during row iteration: %v", err)
	}
	rows.Close() // Close the rows before printing

	// Define colors for each column
	columnColors := []*color.Color{
		color.New(color.FgHiRed),     // ID
		color.New(color.FgHiGreen),   // AGENT_ID
		color.New(color.FgHiYellow),  // COMMAND
		color.New(color.FgHiBlue),    // ARGUMENTS
		color.New(color.FgHiMagenta), // TIMEOUT
		color.New(color.FgHiCyan),    // ACTIVE
		color.New(color.FgHiWhite),   // SUCCESS
		color.New(color.FgHiRed),     // IN_QUEUE
		color.New(color.FgHiGreen),   // TIMED_OUT
		color.New(color.FgHiYellow),  // CREATE_TIME
		color.New(color.FgHiBlue),    // END_TIME
		color.New(color.FgHiMagenta), // RESULT
	}

	if printTasks {
		// Print headers with colors
		headers := []string{"ID", "AGENT_ID", "COMMAND", "ARGUMENTS", "TIMEOUT", "ACTIVE", "SUCCESS", "IN_QUEUE", "TIMED_OUT", "CREATE_TIME", "END_TIME", "RESULT"}
		for i, header := range headers {
			if i < len(headers)-1 {
				columnColors[i].PrintfFunc()("%-*s | ", maxWidths[header], header)
			} else {
				columnColors[i].PrintfFunc()("%-*s", maxWidths[header], header)
			}
		}
		fmt.Println() // Newline after headers

		// Print the data with colors
		for i, task := range tasks {
			columnColors[0].PrintfFunc()("%-*d | ", maxWidths["ID"], task.ID)
			columnColors[1].PrintfFunc()("%-*d | ", maxWidths["AGENT_ID"], task.AgentID)
			columnColors[2].PrintfFunc()("%-*s | ", maxWidths["COMMAND"], task.Command)
			if inQueue {
				columnColors[3].PrintfFunc()("%-*s | ", maxWidths["ARGUMENTS"], inQueueSerializedArgs[i])
			} else {
				columnColors[3].PrintfFunc()("%-*s | ", maxWidths["ARGUMENTS"], notInQueueSerializedArgs[i])
			}
			columnColors[4].PrintfFunc()("%-*d | ", maxWidths["TIMEOUT"], task.Timeout)
			columnColors[5].PrintfFunc()("%-*t | ", maxWidths["ACTIVE"], task.Active)
			columnColors[6].PrintfFunc()("%-*t | ", maxWidths["SUCCESS"], task.Success)
			columnColors[7].PrintfFunc()("%-*t | ", maxWidths["IN_QUEUE"], task.InQueue)
			columnColors[8].PrintfFunc()("%-*t | ", maxWidths["TIMED_OUT"], task.TimedOut)
			columnColors[9].PrintfFunc()("%-*s | ", maxWidths["CREATE_TIME"], task.CreateTime)
			columnColors[10].PrintfFunc()("%-*s | ", maxWidths["END_TIME"], task.EndTime)
			columnColors[11].PrintfFunc()("%-*s\n", maxWidths["RESULT"], task.Result)
		}
	}

	return tasks, nil
}

// UpdateTask updates an existing task in the database.
func UpdateTask(task *Task) error {
	arguments, err := serializeArguments(task.Arguments)
	if err != nil {
		return fmt.Errorf("error in serializing arguments: %w", err)
	}
	// SQL statement includes all fields of the Task struct.
	stmt, err := db.Prepare(`
		UPDATE task
		SET agent_id = ?, command = ?, arguments = ?, timeout = ?, active = ?, success = ?, in_queue = ?, timed_out = ?, create_time = ?, end_time = ?, result = ?
		WHERE id = ?`)
	if err != nil {
		return fmt.Errorf("error preparing SQL statement: %v", err)
	}
	defer stmt.Close()

	// Executing the statement with all fields of the Task struct.
	_, err = stmt.Exec(task.AgentID, task.Command, arguments, task.Timeout, task.Active, task.Success, task.InQueue, task.TimedOut, task.CreateTime, task.EndTime, task.Result, task.ID)
	if err != nil {
		return fmt.Errorf("error updating task: %v", err)
	}

	return nil
}

// DeleteTasksByAgentID deletes all tasks associated with a specific agent ID.
func DeleteTasksByAgentID(agentID int) error {
	_, err := db.Exec("DELETE FROM task WHERE agent_id = ?", agentID)
	if err != nil {
		log.Println("Error deleting tasks by agent ID:", err)
		return err
	}
	return nil
}

// DeleteAllTasks deletes all tasks from the database.
func DeleteAllTasks() error {
	_, err := db.Exec("DELETE FROM task")
	if err != nil {
		log.Println("Error deleting all tasks:", err)
		return err
	}
	return nil
}
