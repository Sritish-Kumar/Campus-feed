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

CREATE TABLE campus_updates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  
  type TEXT NOT NULL CHECK(type IN ('club', 'general')),
  source TEXT,  -- optional: name of admin who posted
  
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  images TEXT,  -- optional: JSON array of image links ["url1", "url2"]
  links TEXT,   -- optional: JSON array of links ["url1", "url2"]
  
  date INTEGER NOT NULL,  -- unix timestamp
  announcement_date DATETIME NOT NULL,  -- datetime format
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  expires_at DATETIME,  -- defaults to date + 7 days
  
  is_published BOOLEAN DEFAULT 0,  -- draft system (0 = draft, 1 = published)
  
  UNIQUE(title, date)  -- prevent duplicate posts with same title and date
);
