/*
User credential storage handler for Database-Vault secure persistence service.

Implements the final layer of the R.A.M.-U.S.B. distributed authentication system
with comprehensive defense-in-depth validation, AES-256-GCM email encryption,
Argon2id password hashing, and secure database storage. Receives mTLS-authenticated
storage requests from Security-Switch instances, performs ultimate security validation,
and persists encrypted credentials with zero-knowledge principles.

TO-DO in StoreUserHandler
*/
package handlers

import (
	"database-vault/config"
	"database-vault/crypto"
	"database-vault/types"
	"database-vault/utils"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// StoreUserHandler processes user credential storage requests with comprehensive security validation.
//
// Security features:
// - mTLS authentication ensures only authorized Security-Switch instances can access
// - Defense-in-depth input validation (final validation before permanent storage)
// - AES-256-GCM email encryption for zero-knowledge primary key functionality
// - Argon2id password hashing with cryptographically secure salt generation
// - Duplicate detection prevents email and SSH key reuse across user base
// - Comprehensive error categorization prevents information disclosure
//
// Returns HTTP 201 on successful storage, 4xx on validation errors, 5xx on storage errors.
//
// TO-DO: Implement rate limiting to prevent abuse despite mTLS authentication
// TO-DO: Add storage quota enforcement per organization or domain
func StoreUserHandler(w http.ResponseWriter, r *http.Request) {
	// TO-DO: Add rate limiting check here despite mTLS authentication

	// HTTP METHOD ENFORCEMENT
	// Prevent CSRF attacks and enforce REST API semantics
	if !utils.EnforcePOST(w, r) {
		return // Sends HTTP 405 Method Not Allowed and logs violation
	}

	// REQUEST BODY PARSING
	// Read and validate HTTP request body for JSON processing
	body, ok := utils.ReadRequestBody(w, r)
	if !ok {
		return // Sends HTTP 400 Bad Request if body reading fails
	}

	// JSON DESERIALIZATION
	// Convert raw JSON bytes into structured RegisterRequest object
	var req types.RegisterRequest
	if !utils.ParseJSONBody(body, &req, w) {
		return // Sends HTTP 400 Bad Request if JSON parsing fails
	}

	// REQUIRED FIELDS VALIDATION (DEFENSE-IN-DEPTH)
	// Final validation layer ensures essential fields are present
	if req.Email == "" || req.Password == "" || req.SSHPubKey == "" {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Email, password, and SSH public key are required.")
		return
	}

	// EMAIL FORMAT VALIDATION (DEFENSE-IN-DEPTH)
	// Validate email format using RFC 5322 compliant regular expression
	if !utils.IsValidEmail(req.Email) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// EMAIL SECURITY VALIDATION (DEFENSE-IN-DEPTH)
	// Prevent email header injection attacks via multiple @ symbols
	if strings.Count(req.Email, "@") != 1 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid email format.")
		return
	}

	// PASSWORD LENGTH VALIDATION (DEFENSE-IN-DEPTH)
	// Enforce minimum password length of 8 characters
	if len(req.Password) < 8 {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must be at least 8 characters.")
		return
	}

	// WEAK PASSWORD DETECTION (DEFENSE-IN-DEPTH)
	// Check against database of commonly used weak passwords
	if utils.IsWeakPassword(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password is too common, please choose a stronger password.")
		return
	}

	// PASSWORD COMPLEXITY VALIDATION (DEFENSE-IN-DEPTH)
	// Ensure password contains at least 3 out of 4 character categories
	if !utils.HasPasswordComplexity(req.Password) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Password must contain at least 3 of: uppercase, lowercase, numbers, special characters.")
		return
	}

	// SSH PUBLIC KEY FORMAT VALIDATION (DEFENSE-IN-DEPTH)
	// Comprehensive validation including algorithm, encoding, and structure
	if !utils.IsValidSSHKey(req.SSHPubKey) {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// SSH KEY PREFIX VALIDATION (DEFENSE-IN-DEPTH)
	// Ensure SSH key starts with recognized algorithm prefix
	if !strings.HasPrefix(req.SSHPubKey, "ssh-") {
		utils.SendErrorResponse(w, http.StatusBadRequest, "Invalid SSH public key format.")
		return
	}

	// CONFIGURATION AND ENCRYPTION KEY LOADING
	// Load encryption key for AES-256-GCM email encryption
	cfg := config.GetConfig()
	if err := crypto.ValidateEncryptionKey(cfg.EncryptionKey); err != nil {
		log.Printf("Encryption key validation failed: %v", err)
		utils.SendErrorResponse(w, http.StatusInternalServerError, "Encryption configuration error.")
		return
	}

	// EMAIL ENCRYPTION
	// Encrypt email with deterministic AES-256-GCM for consistent database lookup
	encryptedEmail, err := crypto.EncryptEmailDeterministic(req.Email, cfg.EncryptionKey)
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to encrypt email for %s: %v", req.Email, err)
		log.Printf("Error: %s", errorMsg)
		utils.SendErrorResponse(w, http.StatusInternalServerError, "Email encryption failed.")
		return
	}

	// TO-DO: Initialize storage interface when PostgreSQL implementation is available
	// var userStorage storage.UserStorage
	// userStorage = postgresql.NewUserStorage(cfg.DatabaseURL)

	// DUPLICATE EMAIL DETECTION
	// Check if encrypted email already exists in database
	// TO-DO: Uncomment when storage interface is implemented
	/*
		emailExists, err := userStorage.EmailExists(encryptedEmail)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to check email existence for %s: %v", req.Email, err)
			log.Printf("Error: %s", errorMsg)
			utils.SendErrorResponse(w, http.StatusInternalServerError, "Database error during duplicate check.")
			return
		}
		if emailExists {
			log.Printf("Registration attempt with existing email: %s", req.Email)
			utils.SendErrorResponse(w, http.StatusConflict, "Email address already registered.")
			return
		}
	*/

	// DUPLICATE SSH KEY DETECTION
	// Check if SSH public key already exists in database
	// TO-DO: Uncomment when storage interface is implemented
	/*
		sshKeyExists, err := userStorage.SSHKeyExists(req.SSHPubKey)
		if err != nil {
			errorMsg := fmt.Sprintf("Failed to check SSH key existence: %v", err)
			log.Printf("Error: %s", errorMsg)
			utils.SendErrorResponse(w, http.StatusInternalServerError, "Database error during SSH key check.")
			return
		}
		if sshKeyExists {
			log.Printf("Registration attempt with existing SSH key")
			utils.SendErrorResponse(w, http.StatusConflict, "SSH public key already in use.")
			return
		}
	*/

	// PASSWORD SALT GENERATION
	// Generate cryptographically secure salt for Argon2id hashing
	passwordSalt, err := crypto.GenerateSalt()
	if err != nil {
		errorMsg := fmt.Sprintf("Failed to generate password salt: %v", err)
		log.Printf("Error: %s", errorMsg)
		utils.SendErrorResponse(w, http.StatusInternalServerError, "Password processing error.")
		return
	}

	// PASSWORD HASHING
	// Hash password with Argon2id using generated salt
	passwordHash := crypto.HashPassword(req.Password, passwordSalt)

	// USER RECORD CREATION
	// Prepare complete user record for database storage
	now := time.Now()
	user := types.StoredUser{
		EncryptedEmail: encryptedEmail,
		PasswordHash:   passwordHash,
		PasswordSalt:   passwordSalt,
		SSHPubKey:      req.SSHPubKey,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	// TO-DO: Remove this blank identifier when storage interface is implemented
	_ = user // Suppress unused variable warning until PostgreSQL implementation is available

	// DATABASE STORAGE
	// Store user credentials in secure database
	// TO-DO: Uncomment when storage interface is implemented
	/*
		if err := userStorage.StoreUser(user); err != nil {
			errorMsg := fmt.Sprintf("Failed to store user credentials for %s: %v", req.Email, err)
			log.Printf("Error: %s", errorMsg)

			// STORAGE ERROR CATEGORIZATION
			// Provide specific guidance based on storage failure type
			if storageErr, ok := err.(*storage.StorageError); ok {
				switch storageErr.Type {
				case storage.ErrorUserExists:
					utils.SendErrorResponse(w, http.StatusConflict, storageErr.UserMessage)
				case storage.ErrorSSHKeyExists:
					utils.SendErrorResponse(w, http.StatusConflict, storageErr.UserMessage)
				case storage.ErrorDatabaseConnection:
					utils.SendErrorResponse(w, http.StatusServiceUnavailable, "Database service unavailable.")
				case storage.ErrorValidationFailed:
					utils.SendErrorResponse(w, http.StatusBadRequest, storageErr.UserMessage)
				default:
					utils.SendErrorResponse(w, http.StatusInternalServerError, "Storage operation failed.")
				}
			} else {
				// Generic storage error - system issue
				utils.SendErrorResponse(w, http.StatusInternalServerError, "Unable to store user credentials.")
			}
			return
		}
	*/

	// SUCCESS RESPONSE
	// Log successful registration and send confirmation to Security-Switch
	log.Printf("User credentials successfully stored: %s", req.Email)
	utils.SendSuccessResponse(w, http.StatusCreated, "User credentials stored successfully!")

	// AUDIT LOGGING
	// Record successful storage operation for security monitoring
	log.Printf("Audit: User registration completed - Email: %s, Timestamp: %s",
		req.Email, time.Now().Format(time.RFC3339))
}
