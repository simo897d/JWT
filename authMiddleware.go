package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/go-redis/redis/v7"
)

func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		redisClient := redis.NewClient(&redis.Options{
			Addr:     "",
			Password: "",
			DB:       0, // use default DB
		})

		authCookie, err := redisClient.Get("jwt").Result()
		if err != nil {
			panic(err)
		}

		jwtoken := strings.Split(authCookie, ".")
		fmt.Println(jwtoken)
		if len(jwtoken) != 3 {
			fmt.Println("Not JWT token")
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			jwtToken := authCookie
			token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("Unexpected signin method: %v", token.Header["alg"])
				}
				return []byte("slartibartfast42dontpanictowel"), nil
			})

			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				ctx := context.WithValue(r.Context(), "props", claims)
				// Access context values in handlers like this
				// props, _ := r.Context().Value("props").(jwt.MapClaims)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			} else {
				fmt.Println(err)
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte("Unauthorized"))
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}
