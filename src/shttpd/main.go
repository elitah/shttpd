package main

import (
	"bufio"
	"compress/gzip"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

func GetRequestHost(r *http.Request) (host string) {
	if nil != r {
		if "" != r.Host {
			host = r.Host
		} else if nil != r.URL && "" != r.URL.Host {
			host = r.URL.Host
		}
		if "" != host {
			h, _, _ := net.SplitHostPort(host)
			if "" != h {
				host = h
			}
		}
	}
	return
}

func regexpGet(expr, content string, n int) []string {
	if re := regexp.MustCompile(expr); nil != re {
		return re.FindAllString(content, n)
	}
	return nil
}

func regexpTest(expr, content string) bool {
	if re := regexp.MustCompile(expr); nil != re {
		return re.MatchString(content)
	}
	return false
}

func regexpFunc(expr, content string, fn func(string) string) string {
	if re := regexp.MustCompile(expr); nil != re {
		return re.ReplaceAllStringFunc(content, fn)
	}
	return ""
}

func proxyURL(proxy, url string) string {
	url = regexpFunc(`\.THUMBNUM\.jpg`, url, func(r string) string {
		return ".15.jpg"
	})
	return regexpFunc(`^(http|https)://`, url, func(r string) string {
		if 's' == r[4] {
			return proxy + "/https/"
		}
		return proxy + "/http/"
	})
}

type rootHandler struct {
	sync.RWMutex

	DomainName string
	UserName   string
	PassWord   string

	IsAnonymous bool

	mClient *http.Client

	mLimit chan byte
}

func NewRootHandle(domain, username, password string) *rootHandler {
	jar, err := cookiejar.New(nil)

	if nil != err {
		fmt.Println(err)
	}

	return &rootHandler{
		DomainName: domain,
		UserName:   username,
		PassWord:   password,

		mClient: &http.Client{
			Transport: &http.Transport{
				Dial: func(netw, addr string) (net.Conn, error) {
					if c, err := net.DialTimeout(netw, addr, 30*time.Second); nil == err {
						return c, nil
					} else {
						return nil, err
					}
				},
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if strings.HasSuffix(GetRequestHost(req), ".xvideos.com") {
					return nil
				}
				return http.ErrUseLastResponse
			},
			Jar: jar,
		},

		mLimit: make(chan byte, 3),
	}
}

func (this *rootHandler) HTTPProxyDo(req *http.Request, dest string) (*http.Response, error) {
	if nil != req && "" != dest {
		this.mLimit <- 1

		defer func() {
			<-this.mLimit
		}()

		if u, err := url.Parse(dest); nil == err {
			var ips [4]byte

			newReq := req.Clone(req.Context())

			rand.Read(ips[:])

			for i, _ := range ips {
				if 0 == i && 223 < ips[i] {
					ips[i] = 223
					continue
				}
				if 0 == ips[i] {
					ips[i]++
				}
				if 250 < ips[i] {
					ips[i] = 250
				}
			}

			if ip := net.IPv4(ips[0], ips[1], ips[2], ips[3]); nil != ip {
				newReq.Header.Set("X-Forwarded-For", ip.String())
				newReq.Header.Set("X-Real-IP", ip.String())
			}

			newReq.URL = u

			if host, _, _ := net.SplitHostPort(u.Host); "" != host {
				newReq.Host = host
			} else {
				newReq.Host = u.Host
			}

			newReq.RequestURI = ""

			this.RLock()
			client := this.mClient
			this.RUnlock()

			return client.Do(newReq)
		} else {
			return nil, err
		}
	} else {
		return nil, syscall.EINVAL
	}
}

func (this *rootHandler) XvideosList(b *strings.Builder, root, proxy string) bool {
	if list := regexpGet(`<div\s+id="video_\d+"\s+data-id=.+<script>xv\.thumbs\.prepareVideo\(\d+\);</script></div>`, b.String(), -1); 0 < len(list) {
		var header string

		if heads := regexpGet(`<div\s+class="pagination.+"><ul>.+</ul></div>`, b.String(), 1); 0 < len(heads) {
			if first := regexpGet(`>1</a></li>`, heads[0], 1); 0 == len(first) {
				heads[0] = strings.Replace(heads[0], `<ul><li>`, fmt.Sprintf(`<ul><li><a href="%s">1</a></li><li>`, root), 1)
			}
			header = strings.Replace(heads[0], `href="/`, fmt.Sprintf(`href="%s/`, root), -1)
		}

		b.Reset()

		fmt.Fprint(b, `<!DOCTYPE html>`)
		fmt.Fprint(b, `<html>`)
		fmt.Fprint(b, `<head>`)
		fmt.Fprint(b, `<title>测试页面</title>`)
		fmt.Fprint(b, `<meta charset="utf-8">`)
		fmt.Fprint(b, `<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">`)
		fmt.Fprint(b, `<meta http-equiv="Cache-Control" content="no-cache" />`)
		fmt.Fprint(b, `<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">`)
		fmt.Fprint(b, `<style>`)
		fmt.Fprint(b, `ul {padding: 0;}`)
		fmt.Fprint(b, `li {display: inline; margin: 0 2px;}`)
		fmt.Fprint(b, `h5 {margin: 0;}`)
		fmt.Fprint(b, `img {width: 100%; max-width: 560px;}`)
		fmt.Fprint(b, `div.content {width: 100%; margin: 1em 0 3em 0;}`)
		fmt.Fprint(b, `</style>`)
		fmt.Fprint(b, `</head>`)
		fmt.Fprint(b, `<body>`)

		fmt.Fprint(b, `<div>`)
		fmt.Fprintf(b, `<form action="%s/" method="get">`, root)
		fmt.Fprint(b, `<input type="text" name="k" style="width: 100%;" />`)
		fmt.Fprint(b, `<input type="submit" value="提交" />`)
		fmt.Fprint(b, `</form>`)
		fmt.Fprint(b, `</div>`)

		fmt.Fprint(b, header)

		fmt.Fprint(b, `<div>`)

		for i, _ := range list {
			if img := regexpGet(`(http|https)://((\w|-)+\.)+\w+/videos/.+\.jpg`, list[i], 1); 0 < len(img) {
				if info := regexpGet(`<p\s+class="title"><a\s+href=".+">.+</a></p>`, list[i], 1); 0 < len(info) {
					if href := regexpGet(`href="/video\d+/(\w|/|-|\.)+"`, info[0], 1); 0 < len(href) {
						if title := regexpGet(`title=".+"`, info[0], 1); 0 < len(title) {
							href[0] = href[0][6 : len(href[0])-1]
							title[0] = title[0][7 : len(title[0])-1]
							fmt.Fprint(b, `<div class="content">`)
							fmt.Fprintf(b, `<a href="%s%s">`, root, href[0])
							fmt.Fprintf(b, `<img src="%s" />`, proxyURL(proxy, img[0]))
							fmt.Fprint(b, `</a>`)
							fmt.Fprintf(b, `<p><a href="%s%s">%s</a></p>`, root, href[0], title[0])
							fmt.Fprint(b, `</div>`)
						}
					}
				}
			}
		}

		fmt.Fprint(b, `</div>`)

		fmt.Fprint(b, `</body>`)
		fmt.Fprint(b, `</html>`)

		return true
	}

	return false
}

func (this *rootHandler) XvideosVideo(b *strings.Builder, root, proxy string) bool {
	if list := regexpGet(`html5player\.set(VideoTitle|VideoUrlLow|VideoUrlHigh|VideoHLS|ThumbUrl)\(.+\);`, b.String(), -1); 0 < len(list) {
		var title string
		var mp4s []string
		var m3u8s []string
		var thumb string

		b.Reset()

		fmt.Fprint(b, `<!DOCTYPE html>`)
		fmt.Fprint(b, `<html>`)
		fmt.Fprint(b, `<head>`)
		fmt.Fprint(b, `<title>测试页面</title>`)
		fmt.Fprint(b, `<meta charset="utf-8">`)
		fmt.Fprint(b, `<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">`)
		fmt.Fprint(b, `<meta http-equiv="Cache-Control" content="no-cache" />`)
		fmt.Fprint(b, `<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">`)
		fmt.Fprint(b, `<link href="https://unpkg.com/video.js/dist/video-js.css" rel="stylesheet">`)
		fmt.Fprint(b, `<script src="https://unpkg.com/video.js/dist/video.js"></script>`)
		fmt.Fprint(b, `<script src="https://unpkg.com/videojs-contrib-hls/dist/videojs-contrib-hls.js"></script>`)
		fmt.Fprint(b, `<style>`)
		fmt.Fprint(b, `video {width: 320px;}`)
		fmt.Fprint(b, `</style>`)
		fmt.Fprint(b, `<body>`)

		fmt.Fprintf(b, `<form action="%s/" method="get">`, root)
		fmt.Fprint(b, `<input type="text" name="k" style="width: 100%;" />`)
		fmt.Fprint(b, `<input type="submit" value="提交" />`)
		fmt.Fprint(b, `</form>`)

		for i, _ := range list {
			if result := regexpGet(`(http|https)://.+'`, list[i], 1); 0 < len(result) {
				result[0] = result[0][:len(result[0])-1]
				if mp4 := regexpGet(`^(http|https)://.+\.mp4\?.+`, result[0], 1); 0 < len(mp4) {
					mp4s = append(mp4s, mp4[0])
				} else if m3u8 := regexpGet(`^(http|https)://.+\.m3u8\?.+`, result[0], 1); 0 < len(m3u8) {
					m3u8s = append(m3u8s, m3u8[0])
				} else if jpg := regexpGet(`^(http|https)://.+\.jpg$`, result[0], 1); 0 < len(jpg) {
					thumb = jpg[0]
				}
			} else if result := regexpGet(`'.+'`, list[i], 1); 0 < len(result) {
				title = result[0][1 : len(result[0])-1]
			}
		}

		fmt.Fprint(b, `<div style="width: 100%; margin: 3em 0;">`)
		fmt.Fprintf(b, `<h5>%s</h5>`, title)
		fmt.Fprint(b, `</div`)

		for i, url := range mp4s {
			fmt.Fprint(b, `<div style="width: 100%; margin: 3em 0;">`)

			fmt.Fprint(b, `<ul>`)
			fmt.Fprintf(b, `<li><a href="%s">mp4 %d</a></li>`, url, i)
			fmt.Fprintf(b, `<li><a href="%s">mp4 %d(Proxy)</a></li>`, proxyURL(proxy, url), i)
			fmt.Fprint(b, `</ul>`)

			fmt.Fprintf(b, `<video id="player_mp4_%d" class="video-js" controls="controls" preload="none" poster="%s">`, i, thumb)
			fmt.Fprintf(b, `<source src="%s" type="video/mp4"></source>`, proxyURL(proxy, url))
			fmt.Fprint(b, `<p class="vjs-no-js">`)
			fmt.Fprint(b, `To view this video please enable JavaScript, and consider upgrading to a web browser that`)
			fmt.Fprint(b, `<a href="http://videojs.com/html5-video-support/" target="_blank">supports HTML5 video</a>`)
			fmt.Fprint(b, `</p>`)
			fmt.Fprint(b, `</video>`)

			fmt.Fprint(b, `</div>`)
		}

		for i, url := range m3u8s {
			fmt.Fprint(b, `<div style="width: 100%; margin: 3em 0;">`)

			fmt.Fprint(b, `<ul>`)
			fmt.Fprintf(b, `<li><a href="%s">m3u8 %d</a></li>`, url, i)
			fmt.Fprintf(b, `<li><a href="%s">m3u8 %d(Proxy)</a></li>`, proxyURL(proxy, url), i)
			fmt.Fprint(b, `</ul>`)

			fmt.Fprintf(b, `<video id="player_hls_%d" class="video-js" controls="controls" preload="none" poster="%s">`, i, thumb)
			fmt.Fprintf(b, `<source src="%s" type="application/x-mpegURL"></source>`, proxyURL(proxy, url))
			fmt.Fprint(b, `<p class="vjs-no-js">`)
			fmt.Fprint(b, `To view this video please enable JavaScript, and consider upgrading to a web browser that`)
			fmt.Fprint(b, `<a href="http://videojs.com/html5-video-support/" target="_blank">supports HTML5 video</a>`)
			fmt.Fprint(b, `</p>`)
			fmt.Fprint(b, `</video>`)

			fmt.Fprint(b, `</div>`)
		}

		fmt.Fprint(b, `<a href="javascript:window.history.go(-1)">go back</a>`)

		fmt.Fprint(b, `<script>`)

		fmt.Fprint(b, `function videoPlay(id) {
var player = videojs('example-video', {"poster": "", "controls": "true"}, function() {
	this.on('play', function() {});
	this.on('pause', function() {});
	this.on('ended', function() {})
});
`)

		for i, _ := range mp4s {
			fmt.Fprintf(b, `videoPlay('player_mp4_%d');`, i)
			fmt.Fprintln(b)
		}

		for i, _ := range m3u8s {
			fmt.Fprintf(b, `videoPlay('player_m3u8_%d');`, i)
			fmt.Fprintln(b)
		}

		fmt.Fprint(b, `</script>`)

		fmt.Fprint(b, `</body>`)
		fmt.Fprint(b, `</html>`)

		return true
	}

	return false
}

func (this *rootHandler) ProxyXvideos(w http.ResponseWriter, resp *http.Response, proxy string) bool {
	var b strings.Builder

	if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/") {
		return false
	}

	if encoding := resp.Header.Get("Content-Encoding"); "" != encoding {
		switch encoding {
		case "gzip":
			if body, err := gzip.NewReader(resp.Body); nil == err {
				io.Copy(&b, body)
			} else {
				return false
			}
		default:
			return false
		}
	} else {
		if 0 < resp.ContentLength {
			b.Grow(int(resp.ContentLength))
		}

		io.Copy(&b, resp.Body)
	}

	if 0 < b.Len() && 1048676 > b.Len() {
		var root string

		root = fmt.Sprintf("%s/%s/%s", proxy, resp.Request.URL.Scheme, resp.Request.URL.Host)

		if this.XvideosList(&b, root, proxy) {
		} else if this.XvideosVideo(&b, root, proxy) {
		} else {
			// 没有匹配到
		}

		io.WriteString(w, b.String())

		return true
	}

	return false
}

func (this *rootHandler) FilterXvideos(w http.ResponseWriter, resp *http.Response, proxy string) bool {
	if nil != w && nil != resp {
		if nil != resp.Request {
			if host := GetRequestHost(resp.Request); "" != host {
				if strings.HasSuffix(host, ".xvideos.com") {
					return this.ProxyXvideos(w, resp, proxy)
				}
			}
		}
	}
	return false
}

func (this *rootHandler) NotFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "Not Found")
}

func (this *rootHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, _ := net.SplitHostPort(r.Host)
	if "" == host {
		host = r.Host
	}
	if this.DomainName == host {
		root := strings.SplitN(r.URL.Path[1:], "/", 2)[0]
		switch root {
		case "file":
			this.ServeFile(w, r)
		case "speed":
			w.Header().Set("Content-Disposition", `attachment; filename="speed.bin"`)
			w.Header().Set("Content-Length", "104857600")
			w.WriteHeader(200)
			io.CopyN(w, rand.Reader, 104857600)
		case "proxy":
			if "GET" == r.Method || "POST" == r.Method {
				var proxy string
				if nil != r.TLS {
					proxy = fmt.Sprintf("https://%s/proxy", this.DomainName)
				} else {
					proxy = fmt.Sprintf("http://%s/proxy", this.DomainName)
				}
				url := r.URL.RequestURI()
				if 7 <= len(url) {
					url = url[len(root)+2:]
					if regexpTest(`^(http|https)+`, url) {
						url = regexpFunc(`^(http|https)/+`, url, func(r string) string {
							if 's' == r[4] {
								return "https://"
							}
							return "http://"
						})
					} else {
						url = r.URL.Query().Get("url")
						if !regexpTest(`^(http|https)`, url) {
							url = "http://" + url
						}
					}
					if resp, err := this.HTTPProxyDo(r, url); nil == err {
						if !this.FilterXvideos(w, resp, proxy) {
							// 回写http头
							for key, value := range resp.Header {
								for _, v := range value {
									w.Header().Add(key, v)
								}
							}
							// 回写HTTP状态
							w.WriteHeader(resp.StatusCode)
							// 回写body
							io.Copy(w, resp.Body)
						}
						// 关闭body
						resp.Body.Close()
					} else {
						fmt.Println(err)

						w.WriteHeader(http.StatusBadRequest)
						io.WriteString(w, "Bad Request")
					}
				} else {
					fmt.Fprint(w, `<!DOCTYPE html>`)
					fmt.Fprint(w, `<html>`)
					fmt.Fprint(w, `<head>`)
					fmt.Fprint(w, `<title>测试页面</title>`)
					fmt.Fprint(w, `<meta charset="utf-8">`)
					fmt.Fprint(w, `<meta name="viewport" content="width=device-width, initial-scale=1, user-scalable=0">`)
					fmt.Fprint(w, `<meta http-equiv="Cache-Control" content="no-cache" />`)
					fmt.Fprint(w, `<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">`)
					fmt.Fprint(w, `</head>`)
					fmt.Fprint(w, `<body>`)

					fmt.Fprint(w, `<div>`)
					fmt.Fprintf(w, `<form action="%s/" method="get">`, proxy)
					fmt.Fprint(w, `<input type="text" name="url" style="width: 100%;" />`)
					fmt.Fprint(w, `<input type="submit" value="提交" />`)
					fmt.Fprint(w, `</form>`)
					fmt.Fprint(w, `</div>`)

					fmt.Fprint(w, `</body>`)
					fmt.Fprint(w, `</html>`)
				}
			} else {
				w.WriteHeader(http.StatusMethodNotAllowed)
				io.WriteString(w, "Method Not Allowed")
			}
		default:
			this.NotFound(w, r)
		}
	} else {
		if "CONNECT" == r.Method {
			this.ServeProxyHttps(w, r)
		} else {
			this.ServeProxyHttp(w, r)
		}
	}
}

func (this *rootHandler) ServeAuth(w http.ResponseWriter, r *http.Request) bool {
	if auth := r.Header.Get("Authorization"); "" != auth {
		//fmt.Println(auth)
		auths := strings.SplitN(auth, " ", 2)
		if 2 == len(auths) {
			switch auths[0] {
			case "Basic":
				if authstr, err := base64.StdEncoding.DecodeString(auths[1]); nil == err {
					//fmt.Println(string(authstr))
					userPwd := strings.SplitN(string(authstr), ":", 2)
					if 2 == len(userPwd) {
						/*
							fmt.Println(this.UserName, len(this.UserName))
							fmt.Println(this.PassWord, len(this.PassWord))
							fmt.Println(userPwd[0], len(userPwd[0]))
							fmt.Println(userPwd[1], len(userPwd[1]))
						*/
						if this.UserName == userPwd[0] &&
							this.PassWord == userPwd[1] {
							return true
						}
					}
				}
			default:
			}
		}
	}
	w.Header().Set("WWW-Authenticate", `Basic realm="Need User Login"`)
	w.WriteHeader(http.StatusUnauthorized)
	return false
}

func (this *rootHandler) ServeFile(w http.ResponseWriter, r *http.Request) {
	if this.ServeAuth(w, r) {
		if p := strings.TrimPrefix(r.URL.Path, "/file"); len(p) < len(r.URL.Path) {
			if "" == p || "/" == p {
				p = "./"
			} else {
				p = "./" + p
			}
			http.ServeFile(w, r, p)
		} else {
			this.NotFound(w, r)
		}
	}
}

func (this *rootHandler) ServeProxyHttp(w http.ResponseWriter, r *http.Request) {
	transport := http.DefaultTransport

	// 处理匿名代理
	if !this.IsAnonymous {
		if clientIP, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			if prior, ok := r.Header["X-Forwarded-For"]; ok {
				clientIP = strings.Join(prior, ", ") + ", " + clientIP
			}
			r.Header.Set("X-Forwarded-For", clientIP)
		}
	}

	// 请求
	if res, err := transport.RoundTrip(r); nil == err {
		// 回写http头
		for key, value := range res.Header {
			for _, v := range value {
				w.Header().Add(key, v)
			}
		}
		// 回写状态码
		w.WriteHeader(res.StatusCode)
		// 回写body
		io.Copy(w, res.Body)
		// 关闭
		res.Body.Close()
	} else {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, err.Error())
	}
}

func (this *rootHandler) ServeProxyHttps(w http.ResponseWriter, r *http.Request) {
	// 拿出host
	host := r.URL.Host

	if hij, ok := w.(http.Hijacker); ok {
		if client, _, err := hij.Hijack(); nil == err {
			if server, err := net.DialTimeout("tcp", host, 30*time.Second); nil == err {
				client.Write([]byte("HTTP/1.0 200 Connection Established\r\n\r\n"))

				// 直通双向复制
				go io.Copy(server, client)
				go io.Copy(client, server)
			} else {
				client.Write([]byte("HTTP/1.0 502 Bad Gateway\r\n\r\n"))
				client.Write([]byte(err.Error()))
			}
		} else {
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, err.Error())
		}
	} else {
		w.WriteHeader(http.StatusBadGateway)
		io.WriteString(w, "HTTP Server does not support hijacking")
	}
}

func main() {
	var help bool
	var domain string
	var addr string
	var username string
	var password string
	var certfile string
	var certkey string
	var anonymous bool

	flag.BoolVar(&help, "h", false, "This Help.")
	flag.StringVar(&domain, "d", "", "Your domain name.")
	flag.StringVar(&addr, "l", ":80", "Local http addr.")
	flag.StringVar(&username, "u", "", "Your username.")
	flag.StringVar(&password, "p", "", "Your password.")
	flag.StringVar(&certfile, "c", "", "Your cert file.")
	flag.StringVar(&certkey, "k", "", "Your cert key.")
	flag.BoolVar(&anonymous, "a", true, "Set anonymous status.")

	flag.Parse()

	if help {
		// for help
	} else if "" != domain && "" != addr && "" != username {
		if "" == password {
			var input string
			var err error
			inputReader := bufio.NewReader(os.Stdin)
			for "" == password {
				fmt.Printf("Input your password: ")
				input, err = inputReader.ReadString('\n')
				if nil == err {
					input = strings.TrimSpace(input)
					if 6 <= len(input) {
						password = input
					} else {
						fmt.Println("Too short. Must be no less than 6 characters.")
					}
				} else {
					if io.EOF == err {
						break
					}
					fmt.Println(err)
				}
			}
		}

		if "" != password && 6 <= len(password) {
			c := make(chan os.Signal, 1)
			exit := make(chan byte)

			token := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", username, password)))

			signal.Notify(c, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)

			go func() {
				root := NewRootHandle(domain, username, password)
				root.IsAnonymous = anonymous
				if "" != certfile && "" != certkey {
					fmt.Println(http.ListenAndServeTLS(addr, certfile, certkey, root))
				} else {
					fmt.Println(http.ListenAndServe(addr, root))
				}
				exit <- 1
			}()

			fmt.Println("#############################################")
			fmt.Printf("Your domain is: %s\n", domain)
			fmt.Printf("Your addrress is: %s\n", addr)
			fmt.Printf("Your username is: %s\n", username)
			fmt.Printf("Your password is: %s\n", password)
			fmt.Printf("Base64 token is: %s\n", token)
			fmt.Printf("Wget url: wget --header 'Authorization: Basic %s' https://%s/file/test.bin\n", token, domain)
			fmt.Println("#############################################")

			fmt.Println("\nEnjoy it!!!\n")

			select {
			case <-c:
			case <-exit:
			}

			signal.Stop(c)

			return
		}
	}

	flag.Usage()
}
