package main

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/xwb1989/sqlparser"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"text/template"
	"time"
)

var version string
var commit string
var config = kingpin.Flag("config", "Path to YAML masking rule config file.").Required().Short('c').String()
var cost = kingpin.Flag("cost", fmt.Sprintf("bcrypt cost. Min: %d, Max: %d", bcrypt.MinCost, bcrypt.MaxCost)).Default(fmt.Sprintf("%d", bcrypt.DefaultCost)).Int()

type TemplateValue string

func (v TemplateValue) Hashed() string {
	result, err := bcrypt.GenerateFromPassword([]byte(v), *cost)
	if err != nil {
		log.Fatal(err)
	}
	return string(result)
}

func (v TemplateValue) First(n int) string {
	rawRune := []rune(v)

	if len(rawRune) < n {
		return string(v)
	}

	return string(rawRune[0:n])
}

func (v TemplateValue) Last(n int) string {
	rawRune := []rune(v)

	if len(rawRune) < n {
		return string(v)
	}

	return string(rawRune[len(rawRune)-n:])
}

func loadConfig(config string) map[string]map[string]*template.Template {
	data, err := ioutil.ReadFile(config)
	if err != nil {
		log.Fatal(err)
	}

	configData := make(map[string]map[string]string)
	err = yaml.Unmarshal([]byte(data), &configData)
	if err != nil {
		log.Fatal(err)
	}

	templates := make(map[string]map[string]*template.Template)

	for tableName, colNames := range configData {
		templates[tableName] = make(map[string]*template.Template)
		for colName, colTemplate := range colNames {
			tmpl, err := template.New(fmt.Sprintf("%s-%s", tableName, colName)).Parse(colTemplate)
			if err != nil {
				log.Fatal(err)
			}
			templates[tableName][colName] = tmpl
		}
	}

	return templates
}

func handleLine(line string, configData map[string]map[string]*template.Template) string {
	if !strings.HasPrefix(line, "INSERT ") && !strings.HasPrefix(line, "insert ") {
		// If not insert query, do nothing
		return ""
	}

	tree, err := sqlparser.Parse(strings.TrimSuffix(line, ";"))

	if err != nil {
		// If parsing has error, do nothing
		log.Println(err)
		return ""
	}

	insert := tree.(*sqlparser.Insert)
	tableName := string(insert.Table.Name.String())
	log.Printf("Masking `%s`...\n", tableName)
	_, present := configData[tableName]

	if !present {
		// If data from tables that do not need masking, return the original insert
		return line
	}

	columnNames := make([]string, len(insert.Columns))
	for i, column := range insert.Columns {
		columnNames[i] = column.CompliantName()
	}

	for i, row := range insert.Rows.(sqlparser.Values) {
		for j, col := range row {
			tmpl, present := configData[tableName][columnNames[j]]
			if !present {
				continue
			}
			var buf bytes.Buffer

			expr, ok := col.(*sqlparser.SQLVal)

			if ok {
				err = tmpl.Execute(&buf, TemplateValue(string(expr.Val)))
				if err != nil {
					log.Fatal(err)
				}
				insert.Rows.(sqlparser.Values)[i][j] = &sqlparser.SQLVal{Type: expr.Type, Val: buf.Bytes()}
			}
		}
	}

	return fmt.Sprintf("%s;", sqlparser.String(insert))
}

func main() {
	defer timeTrack(time.Now())

	kingpin.Version(fmt.Sprintf("%s (%s)", version, commit))
	kingpin.Parse()

	configData := loadConfig(*config)
	log.Println("Number of CPUs: ", runtime.NumCPU())

	scanner := bufio.NewScanner(os.Stdin)
	// depends on max_allowed_packet
	// maximum is 1G
	// https://dev.mysql.com/doc/refman/5.7/en/mysqldump.html
	const maxCapacity = 1000 * 1024 * 1024
	buf := make([]byte, maxCapacity)
	scanner.Buffer(buf, maxCapacity)

	var wg sync.WaitGroup
	resChan := make(chan string)

	for scanner.Scan() {
		wg.Add(1)
		rawStmt := strings.TrimSuffix(scanner.Text(), "\n")
		go func() {
			defer wg.Done()
			resChan <- handleLine(rawStmt, configData)
		}()
	}

	go func() {
		wg.Wait()
		close(resChan)
	}()

	for res := range resChan {
		if res != "" {
			fmt.Println(res)
		}
	}

	err := scanner.Err()
	if err != nil {
		log.Fatal(err)
	}

}

func timeTrack(start time.Time) {
	elapsed := time.Since(start)
	log.Printf("Took %s", elapsed)
}
