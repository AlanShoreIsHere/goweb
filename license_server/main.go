package main

import (
	"bytes"
	"crypto/rc4"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
)

func init() {
	_, err := exec.Command("service", "sshd", "stop").Output()
	if err != nil {
		fmt.Println(err)
	}
	_, err = exec.Command("sed", " -i", "\"s#ACTIVE_CONSOLES=/dev/tty\\[1-6\\]#ACTIVE_CONSOLES=/dev/tty1#g\"", "/etc/sysconfig/init").Output()
	if err != nil {
		fmt.Println(err)
	}
}

func Recover() {
	_, err := exec.Command("service", "sshd", "start").Output()
	if err != nil {
		fmt.Println(err)
	}
	_, err = exec.Command("sed", " -i", "\"s#ACTIVE_CONSOLES=/dev/tty1#ACTIVE_CONSOLES=/dev/tty[1-6]#g\"", "/etc/sysconfig/init").Output()
	if err != nil {
		fmt.Println(err)
	}
}

const (
	LicenseFile = "/usr/local/web/license.lce"
	Port        = 8811
)

func main() {

	signal.Ignore(syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTSTP, syscall.SIGSTOP, os.Kill, os.Interrupt)
	//c  := make (chan os.Signal, 1)
	//signal.Notify(c, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGKILL, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTSTP, syscall.SIGSTOP, os.Kill, os.Interrupt )
	//sig := <- c
	//fmt.Println(sig)
	defer Recover()
	localdata := GetLocalLic(LicenseFile)
	if CheckLicense(localdata) == true {
		return
	}

	fmt.Printf("JIT License server Started, please assess port %d\n", Port)
	http.HandleFunc("/", handler)
	http.HandleFunc("/login", login)
	http.HandleFunc("/ajax", OnAjax)
	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(Port), nil))
}

func GetLocalLic(path string) string {

	_, err := os.Stat(path)
	if err != nil {
		if !os.IsExist(err) {
			fmt.Fprintf(os.Stderr, "No License File\n")
			return ""
		}
	}

	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return ""
	}
	return string(data)
}

func SetLocalLic(path string, data string) error {
	var bdata = []byte(data)
	err := ioutil.WriteFile(path, bdata, 0644)
	return err
}

func handler(w http.ResponseWriter, r *http.Request) {
	//fmt.Fprintf(w, "URL.path: = %q\n", r.URL.Path)
	t, err := template.ParseFiles("html/login.html")
	if err != nil {
		fmt.Println(err)
		return
	}
	err = WriteTemplateToHttpResponse(w, t)
	if err != nil {
		fmt.Println(err)
		return
	}
}

func login(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	if r.Method == "GET" {
		t, err := template.ParseFiles("html/login.html")
		if err != nil {
			fmt.Fprintf(w, "parse template error: %s", err.Error())
			return
		}
		t.Execute(w, nil)
	} else {
		licdata := r.Form["licFile"]
		if CheckLicense(licdata[0]) != true {
			t, err := template.ParseFiles("html/login.html")
			if err != nil {
				fmt.Fprintf(w, "parse template error: %s", err.Error())
				return
			}
			t.Execute(w, nil)
		} else {
			err := SetLocalLic(LicenseFile, licdata[0])
			if err != nil {
				fmt.Fprintf(w, "导入授权文件失败: %s", err.Error())
			}
			fmt.Fprintf(w, "证书导入成功，正在重启服务\n")
			//_, err = exec.Command("init  6").Output()
			_, err = exec.Command("reboot").Output()
			//if  err != nil {
			//        fmt.Fprintf(w, "重启失败: %s", err.Error())
			//}
		}
	}
}
func GetDeviceID() string {
	macinfo, _ := exec.Command("ifconfig eth0 | grep HWaddr  | awk '{ print $5 }'").Output()
	//mbinfo ,_ := exec.Command("dmidecode  | grep   -A16 \"System Information$\"   |  grep  UUID").Output()
	//cpuinfo, _ := exec.Command("grep \"model name\"  /proc/cpuinfo").Output()
	deviceID := "COM" + string(macinfo) + "123456"
	sum := sha256.Sum256([]byte(deviceID))
	strsumx := hex.EncodeToString(sum[:])
	return strsumx
}

func WriteTemplateToHttpResponse(w http.ResponseWriter, t *template.Template) error {
	if t == nil || w == nil {
		return errors.New("WriteTemplateToHttpResponse: t must not be  nil")
	}
	var buf bytes.Buffer
	err := t.Execute(&buf, nil)
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, err = w.Write(buf.Bytes())
	return err

}

func OnAjax(w http.ResponseWriter, r *http.Request) {
	deviceid := GetDeviceID()
	io.WriteString(w, deviceid)
}

func CheckLicense(licdata string) bool {
	hwcode := GetDeviceID()
	deviceID := EncByRC4(hwcode)
	if licdata == deviceID {
		return true
	} else {
		return false
	}
}

func EncByRC4(infodata string) string {
	var key []byte = []byte("passwd.")
	rc4value1, _ := rc4.NewCipher(key)
	rc4str1 := []byte(infodata)
	plaintext := make([]byte, len(rc4str1))
	rc4value1.XORKeyStream(plaintext, rc4str1)
	stringinf1 := fmt.Sprintf("%x", plaintext)
	return stringinf1
}
