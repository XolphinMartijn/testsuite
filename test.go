package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type KnownResults struct {
	WarningsAndErrors map[string]int `json:"warningsAndErrors"`
}

type Finding struct {
	Severity string `json:"Severity"`
	Finding  string `json:"Finding"`
	Linter   string `json:"Linter"`
}

func loadKnownResults(filePath string) (KnownResults, error) {
	var knownResults KnownResults
	fileContent, err := os.ReadFile(filePath)
	if err != nil {
		return knownResults, err
	}

	err = json.Unmarshal(fileContent, &knownResults)
	if err != nil {
		return knownResults, err
	}

	return knownResults, nil
}

func compareWarningsAndErrors(warningsAndErrorsCount map[string]int, knownResults KnownResults) (bool, error) {
	fmt.Println("\nComparing with known results...")
	mismatchFound := false

	for warning, count := range warningsAndErrorsCount {
		if knownCount, ok := knownResults.WarningsAndErrors[warning]; ok {
			if count != knownCount {
				fmt.Printf("Mismatch for %s: found %d, expected %d\n", warning, count, knownCount)
				mismatchFound = true
			} else {
				fmt.Printf("%s matches with count: %d\n", warning, count)
			}
		} else {
			fmt.Printf("%s not found in known results\n", warning)
			mismatchFound = true
		}
	}

	// Check if there are any known warnings that were not found in the current run
	for knownWarning := range knownResults.WarningsAndErrors {
		if _, ok := warningsAndErrorsCount[knownWarning]; !ok {
			fmt.Printf("Warning or error %s exists in known results but was not found in current run\n", knownWarning)
			mismatchFound = true
		}
	}

	return mismatchFound, nil

}

func postPemContent(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	fileContent := string(content)

	cmd := exec.Command("curl", "-s", "-X", "POST", "http://pkimet.al/lintcert",
		"-H", "Content-Type: application/x-www-form-urlencoded",
		"--data-urlencode", fmt.Sprintf("b64input=%s", fileContent))

	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

func main() {
	directory := "pem"
	var pemCount, pkimetalCount int
	warningsAndErrors := make([]string, 0)
	warningsAndErrorsCount := make(map[string]int)

	knownResults, err := loadKnownResults("knownResults.json")
	if err != nil {
		fmt.Println("Error loading known results:", err)
		os.Exit(1)
	}

	err = filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(path, ".pem") {
			pemCount++
			response, err := postPemContent(path)
			if err != nil {
				fmt.Println("Error posting PEM content:", err)
				return err
			}

			var findings []Finding
			if err := json.Unmarshal([]byte(response), &findings); err != nil {
				fmt.Println("Invalid JSON response:", response)
				return err
			}

			for _, finding := range findings {
				if finding.Severity == "fatal" {
					fmt.Println("Fatal severity found in response:", response)
					os.Exit(1)
				}

				if finding.Linter == "pkimetal" {
					pkimetalCount++
				}

				if finding.Severity == "warning" {
					warningsAndErrors = append(warningsAndErrors, finding.Finding)
				}
			}
		}
		return nil
	})

	if err != nil {
		fmt.Println("Error walking through directory:", err)
		return
	}

	if pemCount != pkimetalCount {
		fmt.Println("Mismatch between number of .pem files and number of pkimetal invocations")
		os.Exit(1)
	}

	for _, warning := range warningsAndErrors {
		warningsAndErrorsCount[warning]++
	}

	mismatchFound, err := compareWarningsAndErrors(warningsAndErrorsCount, knownResults)
	if err != nil {
		fmt.Println("Error during comparison:", err)
		os.Exit(1)
	}

	// Exit with code 1 if any mismatch is found
	if mismatchFound {
		fmt.Println("Mismatch found, exiting with error code 1")
		os.Exit(1)
	}

	fmt.Println("All warnings and errors match known results.")

}
