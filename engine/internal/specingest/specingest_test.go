package specingest

import (
	"strings"
	"testing"
)

func TestOpenAPIIngestionJSON(t *testing.T) {
	openAPIRaw := `{
		"openapi": "3.0.0",
		"info": {
			"title": "Petstore API",
			"version": "1.0.0"
		},
		"servers": [
			{"url": "https://api.petstore.com/v1"}
		],
		"paths": {
			"/pets": {
				"get": {
					"summary": "List all pets",
					"parameters": [
						{
							"name": "limit",
							"in": "query",
							"required": false,
							"schema": {"type": "integer"}
						}
					]
				},
				"post": {
					"summary": "Create a pet",
					"requestBody": {
						"content": {
							"application/json": {
								"schema": {
									"type": "object",
									"properties": {
										"name": {"type": "string"},
										"tag": {"type": "string"},
										"age": {"type": "integer"}
									}
								}
							}
						}
					}
				}
			},
			"/pets/{petId}": {
				"get": {
					"summary": "Info for a specific pet",
					"parameters": [
						{
							"name": "petId",
							"in": "path",
							"required": true,
							"schema": {"type": "string"}
						}
					]
				}
			}
		}
	}`

	res, err := Ingest([]byte(openAPIRaw), "openapi.json", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Format != FormatOpenAPI3 {
		t.Fatalf("expected FormatOpenAPI3, got %s", res.Format)
	}
	if res.Title != "Petstore API" {
		t.Fatalf("expected Petstore API title, got %s", res.Title)
	}
	if len(res.Endpoints) != 3 {
		t.Fatalf("expected 3 endpoints, got %d", len(res.Endpoints))
	}

	targets := ToTargets(res)
	if len(targets) == 0 {
		t.Fatal("expected non-empty targets")
	}

	hasPathParamReplaced := false
	for _, target := range targets {
		if strings.Contains(target.URL, "/pets/100") {
			hasPathParamReplaced = true
		}
	}
	if !hasPathParamReplaced {
		t.Errorf("expected path parameter {petId} to be replaced with default value, targets: %+v", targets)
	}
}

func TestPostmanCollectionIngestion(t *testing.T) {
	postmanRaw := `{
		"info": {
			"name": "E-Commerce API",
			"schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
		},
		"item": [
			{
				"name": "User Management",
				"item": [
					{
						"name": "Get User Profile",
						"request": {
							"method": "GET",
							"header": [
								{"key": "Authorization", "value": "Bearer token123"}
							],
							"url": {
								"raw": "https://api.shop.com/users/:userId",
								"host": ["api", "shop", "com"],
								"path": ["users", ":userId"],
								"variable": [
									{"key": "userId", "value": "42"}
								]
							}
						}
					}
				]
			},
			{
				"name": "Apply Coupon",
				"request": {
					"method": "POST",
					"header": [],
					"body": {
						"mode": "urlencoded",
						"urlencoded": [
							{"key": "coupon_code", "value": "SAVE50", "type": "text"}
						]
					},
					"url": {
						"raw": "https://api.shop.com/coupon/apply",
						"host": ["api", "shop", "com"],
						"path": ["coupon", "apply"]
					}
				}
			}
		]
	}`

	res, err := Ingest([]byte(postmanRaw), "collection.json", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Format != FormatPostman {
		t.Fatalf("expected FormatPostman, got %s", res.Format)
	}
	if len(res.Endpoints) != 2 {
		t.Fatalf("expected 2 endpoints, got %d", len(res.Endpoints))
	}

	targets := ToTargets(res)
	hasCouponParam := false
	for _, target := range targets {
		if target.Parameter == "coupon_code" && target.Location == "form" {
			hasCouponParam = true
		}
	}
	if !hasCouponParam {
		t.Errorf("expected form parameter coupon_code, targets: %+v", targets)
	}
}

func TestHARIngestion(t *testing.T) {
	harRaw := `{
		"log": {
			"version": "1.2",
			"creator": {"name": "Chrome DevTools", "version": "120.0"},
			"entries": [
				{
					"request": {
						"method": "GET",
						"url": "https://example.com/api/v1/search?q=test&page=1",
						"httpVersion": "HTTP/2.0",
						"headers": [
							{"name": "Accept", "value": "application/json"}
						],
						"queryString": [
							{"name": "q", "value": "test"},
							{"name": "page", "value": "1"}
						],
						"cookies": []
					}
				},
				{
					"request": {
						"method": "GET",
						"url": "https://example.com/static/logo.png",
						"httpVersion": "HTTP/2.0",
						"headers": [],
						"queryString": [],
						"cookies": []
					}
				}
			]
		}
	}`

	res, err := Ingest([]byte(harRaw), "traffic.har", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if res.Format != FormatHAR {
		t.Fatalf("expected FormatHAR, got %s", res.Format)
	}
	// Static png must be filtered out
	if len(res.Endpoints) != 1 {
		t.Fatalf("expected 1 endpoint (PNG filtered out), got %d", len(res.Endpoints))
	}
	if len(res.Endpoints[0].Parameters) != 2 {
		t.Fatalf("expected 2 query parameters (q, page), got %d", len(res.Endpoints[0].Parameters))
	}
}
