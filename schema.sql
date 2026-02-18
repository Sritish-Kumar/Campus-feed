CREATE TABLE announcements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  type TEXT NOT NULL CHECK(type IN ('college', 'club', 'general')),
  source TEXT NOT NULL CHECK(source IN ('admin', 'scraper')),

  title TEXT NOT NULL,
  content TEXT,
  link TEXT,

  announcement_date DATETIME NOT NULL,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  expires_at DATETIME,

  is_published BOOLEAN DEFAULT 1,

  UNIQUE(title, announcement_date)
);
