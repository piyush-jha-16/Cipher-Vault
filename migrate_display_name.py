import sqlite3

def migrate_display_name():
    """Add display_name column to users table and populate it with current usernames"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    try:
        # Check if display_name column already exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        
        if 'display_name' in columns:
            print("✅ display_name column already exists!")
            return
        
        print("Adding display_name column...")
        
        # Add display_name column
        cursor.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
        
        # Populate display_name with current username values
        cursor.execute("UPDATE users SET display_name = username")
        
        conn.commit()
        
        # Verify the migration
        cursor.execute("SELECT id, username, display_name FROM users")
        users = cursor.fetchall()
        
        print(f"\n✅ Migration successful! Updated {len(users)} users:")
        for user in users:
            print(f"   ID: {user[0]}, Username: {user[1]}, Display Name: {user[2]}")
        
    except Exception as e:
        print(f"❌ Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_display_name()
