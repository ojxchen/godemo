package main

import (
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"net/http"
	"time"
)

var secretKey = []byte("xuchen_demo") // 用于签名的密钥

// LoginRequest 登录请求结构体
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse 登录成功返回的结构体
type LoginResponse struct {
	Token string `json:"token"`
}

// 生成 JWT Token
func generateToken(username string) (string, error) {
	claims := jwt.StandardClaims{
		Subject:   username,
		Issuer:    "myapp",
		ExpiresAt: time.Now().Add(time.Minute * 30).Unix(), // 设置 token 过期时间为 30分钟
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secretKey)
}

// 登录接口
func login(c *gin.Context) {
	var req LoginRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
		return
	}

	// 简单的用户名和密码验证
	if req.Username == "admin" && req.Password == "password" {
		// 生成 token
		token, err := generateToken(req.Username)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
			return
		}

		// 返回 token
		c.JSON(http.StatusOK, LoginResponse{Token: token})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
	}
}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:8080"}, // 允许的前端域名
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))
	r.POST("/login", login)

	err := r.Run(":8888")
	if err != nil {
		return
	}
}
