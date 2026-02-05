-- SecureSight Database Initialization Script
-- This script runs when PostgreSQL container is first created

-- Create extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create indexes for better performance
-- (Tables are created by SQLAlchemy, this is for additional optimization)

-- Grant permissions
GRANT ALL PRIVILEGES ON DATABASE securesight TO securesight;

-- Create indexes after tables are created (run manually or via migrations)
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_severity ON alerts(severity);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_status ON alerts(status);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_alerts_created_at ON alerts(created_at);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
-- CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
