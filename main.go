package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"regexp" // Add this import
	"strings"

	"ferri/database"
	"ferri/processors"
	"ferri/utils"
)

func main() {
	dbPath := utils.ExpandPath("~/bugbounty/db/bounty.db")
	
	// Check if there's any data on stdin
	if !utils.HasStdinData() {
		fmt.Printf("📭 No input provided via stdin\n")
		fmt.Printf("💾 Ensuring database exists: %s\n", dbPath)
		
		// Ensure database exists before exiting
		if err := database.EnsureDBExists(dbPath); err != nil {
			log.Fatalf("❌ Error ensuring database exists: %v\n", err)
		}
		
		fmt.Printf("✅ Database is ready for use\n")
		fmt.Printf("💡 Usage: echo 'example.com' | ferri\n")
		fmt.Printf("💡 Usage: subfinder -d example.com | ferri\n")
		os.Exit(0)
	}

	// There is stdin data, proceed with normal processing
	toolName := utils.DetectTool()

	fmt.Printf("🛠️  Auto-detected tool: %s\n", toolName)
	fmt.Printf("💾 Database: %s\n", dbPath)

	// Ensure database exists
	if err := database.EnsureDBExists(dbPath); err != nil {
		log.Fatalf("❌ Error ensuring database exists: %v\n", err)
	}

	// Initialize database connection
	db, err := database.InitDB(dbPath)
	if err != nil {
		log.Fatalf("❌ Error initializing database: %v\n", err)
	}
	defer db.Close()

	// Read from stdin
	scanner := bufio.NewScanner(os.Stdin)
	var targets []string
	var firstTarget string

	fmt.Printf("📥 Reading from stdin...\n")
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		targets = append(targets, line)
		if firstTarget == "" {
			firstTarget = line
		}
	}

	if len(targets) == 0 {
		fmt.Println("❌ No valid targets found in stdin")
		os.Exit(1)
	}

	fmt.Printf("📋 Found %d targets to process\n", len(targets))

	// Extract domain from first target for program creation
	domain := firstTarget
	if strings.Contains(firstTarget, "://") {
		// Extract domain from URL
		re := regexp.MustCompile(`(?i)https?://([^/]+)`)
		if matches := re.FindStringSubmatch(firstTarget); len(matches) > 1 {
			domain = matches[1]
		}
	} else if strings.Contains(firstTarget, ".") {
		// Assume it's a domain or subdomain
		domain = firstTarget
	}

	fmt.Printf("🌐 Extracted domain: %s\n", domain)

	// Get or create program
	programID, err := processors.GetOrCreateProgram(db, domain)
	if err != nil {
		log.Fatalf("❌ Error getting/creating program: %v\n", err)
	}

	// Process all targets
	processedCount := 0
	for _, target := range targets {
		targetID, err := processors.GetOrCreateTarget(db, target, toolName, programID)
		if err != nil {
			log.Printf("⚠️ Error with target %s: %v\n", target, err)
			continue
		}

		err = processors.AddReconData(db, targetID, toolName, target, "Discovered via "+toolName)
		if err != nil {
			log.Printf("⚠️ Error adding recon data for %s: %v\n", target, err)
			continue
		}

		processedCount++
		fmt.Printf("✅ %s\n", target)
	}

	fmt.Printf("\n🎉 Completed! Processed %d/%d targets for program ID: %d\n", 
		processedCount, len(targets), programID)
	
	if processedCount > 0 {
		fmt.Printf("💡 Next: Use 'ferro' to analyze your data!\n")
	} else {
		fmt.Printf("❌ No targets were processed successfully\n")
		os.Exit(1)
	}
}
