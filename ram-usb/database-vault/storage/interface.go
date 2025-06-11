/*
Storage interface definitions for Database-Vault secure credential persistence.

Provides abstract interfaces for user credential storage operations without
concrete PostgreSQL implementation details. Defines contracts for encrypted
email storage, password hash persistence, SSH key management, and duplicate
detection within the zero-knowledge R.A.M.-U.S.B. authentication system.
Enables flexible storage backend implementation while maintaining security guarantees.
*/
package storage

import (
	"database-vault/types"
	"time"
)

// UserStorage defines the interface for secure user credential storage operations.
//
// Security features:
// - Encrypted email primary key operations for zero-knowledge user identification
// - Secure password hash storage with Argon2id and cryptographic salt
// - SSH public key persistence for Storage-Service authentication
// - Duplicate detection prevents email and SSH key reuse across user base
// - Transaction-safe operations ensure data consistency and integrity
//
// Implementation will handle PostgreSQL connection management, encryption, and audit logging.
type UserStorage interface {
	// StoreUser persists new user credentials with encrypted email and hashed password.
	//
	// Security features:
	// - Atomic transaction ensures complete user record creation or rollback
	// - Encrypted email serves as primary key for zero-knowledge identification
	// - Argon2id password hash with unique salt prevents rainbow table attacks
	// - SSH key storage enables authenticated Storage-Service access
	// - Timestamp tracking for security auditing and account lifecycle management
	//
	// Returns error if storage fails, email/SSH key already exists, or validation fails.
	StoreUser(user types.StoredUser) error

	// GetUserByEncryptedEmail retrieves complete user record by encrypted email primary key.
	//
	// Security features:
	// - Encrypted email lookup prevents user enumeration attacks
	// - Complete credential retrieval for authentication verification
	// - Constant-time operation structure prevents timing side-channel attacks
	// - Secure handling of non-existent users without information disclosure
	//
	// Returns user record or nil if not found, error if database operation fails.
	GetUserByEncryptedEmail(encryptedEmail string) (*types.StoredUser, error)

	// EmailExists checks if encrypted email is already registered for duplicate prevention.
	//
	// Security features:
	// - Encrypted email comparison preserves privacy during uniqueness validation
	// - Prevents timing attacks through consistent response structure
	// - No user data exposure during existence check operations
	// - Audit logging for registration attempt monitoring
	//
	// Returns true if encrypted email exists, false otherwise, error if check fails.
	EmailExists(encryptedEmail string) (bool, error)

	// SSHKeyExists verifies SSH public key uniqueness across entire user base.
	//
	// Security features:
	// - Prevents SSH key reuse which could compromise Storage-Service access control
	// - Plaintext SSH key comparison for accurate duplicate detection
	// - No user association disclosure during uniqueness validation
	// - Efficient index-based lookup for performance at scale
	//
	// Returns true if SSH key is already registered, false otherwise, error if check fails.
	SSHKeyExists(sshKey string) (bool, error)

	// UpdateUser modifies existing user credentials with version control and audit trail.
	//
	// Security features:
	// - Atomic transaction ensures partial update prevention
	// - UpdatedAt timestamp tracking for security monitoring
	// - Encrypted email immutability prevents primary key confusion
	// - Password and SSH key update validation with duplicate checking
	//
	// Returns error if user not found, validation fails, or database operation fails.
	UpdateUser(encryptedEmail string, updates UserUpdateRequest) error

	// DeleteUser removes user credentials with secure data wiping and audit logging.
	//
	// Security features:
	// - Soft delete with audit trail preservation for security compliance
	// - Secure credential cleanup prevents data remnants
	// - Transaction-safe removal ensures data consistency
	// - Permanent deletion option for GDPR compliance
	//
	// Returns error if user not found or deletion operation fails.
	DeleteUser(encryptedEmail string, permanent bool) error

	// GetUserStats retrieves anonymous usage statistics for monitoring and capacity planning.
	//
	// Security features:
	// - No personally identifiable information in statistics
	// - Aggregate data only for operational monitoring
	// - Registration trend analysis without user enumeration
	//
	// Returns statistics summary or error if collection fails.
	GetUserStats() (*UserStats, error)

	// HealthCheck verifies database connectivity and storage system integrity.
	//
	// Security features:
	// - Connection validation without exposing credentials
	// - Storage capacity monitoring for operational awareness
	// - Performance metrics for security incident detection
	//
	// Returns health status or error if system is unavailable.
	HealthCheck() (*StorageHealth, error)
}

// UserUpdateRequest defines fields that can be modified for existing users.
//
// Security features:
// - Immutable encrypted email prevents primary key confusion
// - Optional field updates allow partial credential modification
// - New password hash validation with fresh salt generation
// - SSH key uniqueness verification before update acceptance
//
// Used by UpdateUser for secure credential modification operations.
type UserUpdateRequest struct {
	NewPasswordHash *string `json:"new_password_hash,omitempty"` // Updated Argon2id hash with new salt
	NewPasswordSalt *string `json:"new_password_salt,omitempty"` // Fresh cryptographic salt for new password
	NewSSHPubKey    *string `json:"new_ssh_key,omitempty"`       // Updated SSH public key for storage access
}

// UserStats provides anonymous usage statistics for operational monitoring.
//
// Security features:
// - No personally identifiable information exposed
// - Aggregate data only for capacity planning and trend analysis
// - Registration patterns without user enumeration capability
//
// Used for Database-Vault operational monitoring and security analytics.
type UserStats struct {
	TotalUsers         int       `json:"total_users"`         // Total registered user count
	ActiveUsers        int       `json:"active_users"`        // Users with recent activity
	RegistrationsToday int       `json:"registrations_today"` // New registrations in last 24 hours
	LastRegistration   time.Time `json:"last_registration"`   // Most recent registration timestamp
	StorageUsageBytes  int64     `json:"storage_usage_bytes"` // Database storage consumption
}

// StorageHealth represents database and storage system health status.
//
// Security features:
// - Connection status without credential exposure
// - Performance metrics for security incident detection
// - Storage capacity monitoring for operational awareness
//
// Used for Database-Vault health monitoring and alerting systems.
type StorageHealth struct {
	Connected       bool          `json:"connected"`         // Database connectivity status
	ResponseTime    time.Duration `json:"response_time"`     // Average query response time
	ConnectionCount int           `json:"connection_count"`  // Active database connections
	StorageCapacity string        `json:"storage_capacity"`  // Available storage space
	LastHealthCheck time.Time     `json:"last_health_check"` // Health check execution timestamp
}

// StorageConfig holds database connection and configuration parameters.
//
// Security features:
// - Secure connection string handling with credentials protection
// - Connection pooling configuration for performance and security
// - SSL/TLS enforcement for encrypted database communication
// - Timeout configuration prevents hanging connections
//
// Used during UserStorage implementation initialization and configuration.
type StorageConfig struct {
	DatabaseURL        string        `json:"database_url"`         // PostgreSQL connection string with credentials
	MaxConnections     int           `json:"max_connections"`      // Connection pool maximum size
	ConnectionTimeout  time.Duration `json:"connection_timeout"`   // Database connection timeout
	QueryTimeout       time.Duration `json:"query_timeout"`        // Individual query execution timeout
	SSLMode            string        `json:"ssl_mode"`             // SSL/TLS mode (require, verify-full, etc.)
	EnableQueryLogging bool          `json:"enable_query_logging"` // SQL query audit logging
}

// StorageError represents Database-Vault storage operation error conditions.
//
// Security features:
// - Categorized error types prevent information disclosure through error analysis
// - Internal error details separation from client-facing messages
// - Audit trail creation for security monitoring and incident response
// - Standardized error classification for consistent handling
//
// Used for detailed storage error handling and security audit logging.
type StorageError struct {
	Type        StorageErrorType `json:"type"`         // Categorized error type
	Message     string           `json:"message"`      // Detailed internal error description
	UserMessage string           `json:"user_message"` // Sanitized error message for Security-Switch response
	Timestamp   time.Time        `json:"timestamp"`    // Error occurrence time
	Operation   string           `json:"operation"`    // Storage operation that failed
}

// StorageErrorType defines categories of storage operation failures.
//
// Security features:
// - Standardized error classification prevents information disclosure
// - Consistent error handling across all storage operations
// - Security-focused error categorization for audit analysis
//
// Used for error classification and appropriate response determination.
type StorageErrorType string

const (
	// User-related errors
	ErrorUserNotFound    StorageErrorType = "user_not_found"    // User does not exist
	ErrorUserExists      StorageErrorType = "user_exists"       // Email already registered
	ErrorSSHKeyExists    StorageErrorType = "ssh_key_exists"    // SSH key already in use
	ErrorInvalidUserData StorageErrorType = "invalid_user_data" // User data validation failed

	// Database operation errors
	ErrorDatabaseConnection  StorageErrorType = "database_connection"  // Database connectivity failure
	ErrorQueryExecution      StorageErrorType = "query_execution"      // SQL query execution failure
	ErrorTransactionFailed   StorageErrorType = "transaction_failed"   // Database transaction rollback
	ErrorConstraintViolation StorageErrorType = "constraint_violation" // Database constraint violation

	// System errors
	ErrorEncryptionFailed StorageErrorType = "encryption_failed" // Email encryption/decryption failure
	ErrorValidationFailed StorageErrorType = "validation_failed" // Input validation failure
	ErrorUnknown          StorageErrorType = "unknown"           // Unclassified error
)

// Error implements the error interface for StorageError.
//
// Returns the internal detailed error message for logging and debugging purposes.
func (e *StorageError) Error() string {
	return e.Message
}

// NewStorageError creates a new StorageError with categorization and timestamps.
//
// Security features:
// - Automatic timestamp assignment for audit trail creation
// - Error type categorization for consistent handling
// - Separation of internal and user-facing error messages
//
// Returns configured StorageError for comprehensive error handling.
func NewStorageError(errorType StorageErrorType, operation, message, userMessage string) *StorageError {
	return &StorageError{
		Type:        errorType,
		Message:     message,
		UserMessage: userMessage,
		Timestamp:   time.Now(),
		Operation:   operation,
	}
}
