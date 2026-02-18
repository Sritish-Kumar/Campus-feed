// SOA ITER News & Events Scraper
// Scrapes from RSS feed and posts to campus-feed worker

const WORKER_URL = process.env.WORKER_URL || 'http://localhost:8787';
const ADMIN_KEY = process.env.ADMIN_KEY;
const RSS_URL = 'https://www.soa.ac.in/iter-news-and-events?format=rss';

async function postAnnouncement(announcement) {
  try {
    const response = await fetch(`${WORKER_URL}/admin/create`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ADMIN_KEY
      },
      body: JSON.stringify(announcement)
    });

    if (!response.ok) {
      console.error(`❌ Failed to post: ${announcement.title}`);
    } else {
      console.log(`✅ Posted: ${announcement.title}`);
    }
  } catch (error) {
    console.error(`❌ Error posting ${announcement.title}:`, error.message);
  }
}

function parseDate(dateString) {
  // Convert RSS date (e.g., "Thu, 29 Jan 2026 12:57:19 +0000") to YYYY-MM-DD
  const date = new Date(dateString);
  return date.toISOString().split('T')[0];
}

function cleanDescription(description) {
  // Remove HTML tags and extract meaningful content
  if (!description) return null;
  
  // Remove CDATA
  let cleaned = description.replace(/<!\[CDATA\[(.*?)\]\]>/gs, '$1');
  
  // Remove HTML tags
  cleaned = cleaned.replace(/<[^>]*>/g, ' ');
  
  // Decode HTML entities
  cleaned = cleaned
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
  
  // Clean whitespace
  cleaned = cleaned.replace(/\s+/g, ' ').trim();
  
  // Return null if too short or just button text
  if (cleaned.length < 10 || cleaned.match(/^(learn more|click here|soa.?iter)$/i)) {
    return null;
  }
  
  return cleaned.substring(0, 500); // Limit length
}

async function parseRSSFeed(xml) {
  const announcements = [];
  
  // Extract all <item> blocks
  const itemRegex = /<item>(.*?)<\/item>/gs;
  const items = [...xml.matchAll(itemRegex)];
  
  for (const [, itemContent] of items) {
    // Extract fields - try both CDATA and plain text
    let titleMatch = itemContent.match(/<title><!\[CDATA\[(.*?)\]\]><\/title>/s);
    if (!titleMatch) {
      titleMatch = itemContent.match(/<title>(.*?)<\/title>/s);
    }
    
    const linkMatch = itemContent.match(/<link>(.*?)<\/link>/s);
    const dateMatch = itemContent.match(/<pubDate>(.*?)<\/pubDate>/s);
    const descMatch = itemContent.match(/<description>(.*?)<\/description>/s);
    
    if (titleMatch && linkMatch && dateMatch) {
      const title = titleMatch[1].trim();
      const link = linkMatch[1].trim();
      const pubDate = parseDate(dateMatch[1]);
      const content = descMatch ? cleanDescription(descMatch[1]) : null;
      
      announcements.push({
        type: 'college',
        source: 'scraper',
        title: title,
        content: content,
        link: link,
        announcement_date: pubDate,
        expires_at: null
      });
    }
  }
  
  return announcements;
}

async function scrape() {
  console.log(`🔍 Scraping SOA ITER News & Events...`);
  console.log(`📡 Fetching RSS feed: ${RSS_URL}`);
  
  try {
    const response = await fetch(RSS_URL);
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const xml = await response.text();
    const announcements = await parseRSSFeed(xml);
    
    console.log(`\n📋 Found ${announcements.length} announcements`);
    console.log(`📤 Posting to ${WORKER_URL}...\n`);
    
    for (const announcement of announcements) {
      await postAnnouncement(announcement);
      // Small delay to avoid overwhelming the worker
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    
    console.log(`\n✨ Scraping complete!`);
    
  } catch (error) {
    console.error('❌ Scraping failed:', error.message);
    process.exit(1);
  }
}

scrape();
