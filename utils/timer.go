package utils

import (
	"fmt"
	"os"
	"strings"
	"time"
)

type timer struct{
	repeat int
	file *os.File
	currentTest map[string]time.Time
	averageTime map[string]time.Duration
}

func NewTimer(testName string, repeat int) *timer {
	t := new(timer)

	fileName := strings.Split(testName, "/")[0][4:]
	filePath := "../../../testResult/" + fileName + ".txt"

	if file, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666);err != nil {
		panic(err)
	}else{
		t.file = file
		if _, err := file.WriteString(strings.Split(testName, "/")[1] + "\n"); err!=nil{
			panic(err)
		}
	}

	t.currentTest = make(map[string]time.Time)
	t.averageTime = make(map[string]time.Duration)
	t.repeat = repeat
	
	return t
}

func (t *timer) Start(name string) {
	t.currentTest[name] = time.Now()
}

func (t *timer) End(name string) {
	end := time.Since(t.currentTest[name])
	if _, exist := t.averageTime[name]; !exist {
		t.averageTime[name] = end
	}else{
		t.averageTime[name] += end
	}
}

func (t *timer) average(){
	for name_, time_ := range t.averageTime{
		t.averageTime[name_] = time_ / time.Duration(t.repeat)
	}
}

func (t *timer) AverageAndEnd() {
	t.average()

	if _, err := t.file.WriteString("repeat "+ fmt.Sprintf("%d, ", t.repeat) + "Average time:\n"); err!=nil{
		panic(err)
	}

	for name_, time_ := range t.averageTime{
		if _, err := t.file.WriteString(name_ + ": " + fmt.Sprintf("%.2fms", float64(time_)/1e6) + "\n"); err!=nil{
			panic(err)
		}
	}

	if _, err := t.file.WriteString("\n"); err!=nil{
		panic(err)
	}

	t.file.Close()
}