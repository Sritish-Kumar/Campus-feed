/**
 * Campus Feed API - Secure version with rate limiting and validation
 */

// Rate limiting storage
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX_REQUESTS = 60; // 60 requests per minute per IP

// Field whitelist for public API
const PUBLIC_FIELDS = ['id', 'type', 'source', 'title', 'content', 'link', 'announcement_date', 'expires_at'];

// Validation functions
function validateAnnouncementData(data) {
  const errors = [];
  
  // Required fields
  if (!data.type || !['college', 'club', 'general'].includes(data.type)) {
    errors.push('Invalid type. Must be: college, club, or general');
  }
  
  if (!data.source || !['admin', 'scraper'].includes(data.source)) {
    errors.push('Invalid source. Must be: admin or scraper');
  }
  
  if (!data.title || typeof data.title !== 'string' || data.title.length < 3) {
    errors.push('Title is required (min 3 characters)');
  }
  
  if (data.title && data.title.length > 500) {
    errors.push('Title too long (max 500 characters)');
  }
  
  if (data.content && typeof data.content !== 'string') {
    errors.push('Content must be a string');
  }
  
  if (data.content && data.content.length > 5000) {
    errors.push('Content too long (max 5000 characters)');
  }
  
  if (!data.announcement_date || !isValidDate(data.announcement_date)) {
    errors.push('Valid announcement_date is required (YYYY-MM-DD)');
  }
  
  if (data.link && !isValidUrl(data.link)) {
    errors.push('Link must be a valid URL');
  }
  
  if (data.expires_at && !isValidDate(data.expires_at)) {
    errors.push('expires_at must be a valid date (YYYY-MM-DD)');
  }
  
  return errors;
}

function validateCampusUpdateData(data) {
  const errors = [];
  
  // Required fields
  if (!data.type || !['club', 'general'].includes(data.type)) {
    errors.push('Invalid type. Must be: club or general');
  }
  
  if (!data.title || typeof data.title !== 'string' || data.title.length < 3) {
    errors.push('Title is required (min 3 characters)');
  }
  
  if (data.title && data.title.length > 500) {
    errors.push('Title too long (max 500 characters)');
  }
  
  if (!data.content || typeof data.content !== 'string' || data.content.length < 1) {
    errors.push('Content is required');
  }
  
  if (data.content && data.content.length > 5000) {
    errors.push('Content too long (max 5000 characters)');
  }
  
  if (!data.announcement_date || !isValidDate(data.announcement_date)) {
    errors.push('Valid announcement_date is required (YYYY-MM-DD)');
  }
  
  // Optional source
  if (data.source && typeof data.source !== 'string') {
    errors.push('Source must be a string');
  }
  
  // Validate images array if provided
  if (data.images) {
    if (!Array.isArray(data.images)) {
      errors.push('Images must be an array');
    } else {
      data.images.forEach((img, idx) => {
        if (!isValidUrl(img)) {
          errors.push(`Invalid URL in images[${idx}]: ${img}`);
        }
      });
    }
  }
  
  // Validate links array if provided
  if (data.links) {
    if (!Array.isArray(data.links)) {
      errors.push('Links must be an array');
    } else {
      data.links.forEach((link, idx) => {
        if (!isValidUrl(link)) {
          errors.push(`Invalid URL in links[${idx}]: ${link}`);
        }
      });
    }
  }
  
  if (data.expires_at && !isValidDate(data.expires_at)) {
    errors.push('expires_at must be a valid date (YYYY-MM-DD)');
  }
  
  if (data.is_published !== undefined && typeof data.is_published !== 'boolean' && data.is_published !== 0 && data.is_published !== 1) {
    errors.push('is_published must be a boolean or 0/1');
  }
  
  return errors;
}

function isValidDate(dateString) {
  const regex = /^\d{4}-\d{2}-\d{2}$/;
  if (!regex.test(dateString)) return false;
  const date = new Date(dateString);
  return date instanceof Date && !isNaN(date);
}

function isValidUrl(string) {
  try {
    const url = new URL(string);
    return url.protocol === 'http:' || url.protocol === 'https:';
  } catch (_) {
    return false;
  }
}

function sanitizeString(str) {
  if (!str) return null;
  // Basic XSS prevention - remove potential script tags
  return str.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
            .trim();
}

function getClientIP(request) {
  return request.headers.get('cf-connecting-ip') || 
         request.headers.get('x-forwarded-for') || 
         'unknown';
}

async function checkRateLimit(env, ip, endpoint) {
  const key = `ratelimit:${endpoint}:${ip}`;
  const now = Date.now();
  
  // Get current count
  const count = await env.RATE_LIMIT?.get(key);
  const current = count ? parseInt(count) : 0;
  
  if (current >= RATE_LIMIT_MAX_REQUESTS) {
    return false;
  }
  
  // Increment counter with expiration
  await env.RATE_LIMIT?.put(key, (current + 1).toString(), {
    expirationTtl: 60
  });
  
  return true;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const clientIP = getClientIP(request);

    // CORS headers for all routes
    // To restrict to specific domain, change '*' to 'https://yourdomain.com'
    // For multiple domains, check origin dynamically (see below)
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*', // Change to 'https://yourdomain.com' for production
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, x-api-key',
      'Access-Control-Max-Age': '86400',
    };

    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: corsHeaders });
    }

    // =========================
    // PUBLIC FEED
    // =========================
    if (url.pathname === "/feed" && request.method === "GET") {
      // Rate limiting (optional for public endpoint)
      if (env.RATE_LIMIT) {
        const allowed = await checkRateLimit(env, clientIP, 'feed');
        if (!allowed) {
          return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
            status: 429,
            headers: {
              ...corsHeaders,
              'Content-Type': 'application/json',
              'Retry-After': '60'
            }
          });
        }
      }

      const { results } = await env.DB.prepare(`
        SELECT id, type, source, title, content, link, announcement_date, expires_at
        FROM announcements
        WHERE is_published = 1
        ORDER BY announcement_date DESC
        LIMIT 20
      `).all();

      return new Response(JSON.stringify(results), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=60',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }

    // =========================
    // PUBLIC UPDATES
    // =========================
    if (url.pathname === "/updates" && request.method === "GET") {
      // Rate limiting (optional for public endpoint)
      if (env.RATE_LIMIT) {
        const allowed = await checkRateLimit(env, clientIP, 'updates');
        if (!allowed) {
          return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
            status: 429,
            headers: {
              ...corsHeaders,
              'Content-Type': 'application/json',
              'Retry-After': '60'
            }
          });
        }
      }

      // Parse query parameters for filtering and pagination
      const params = new URL(request.url).searchParams;
      const type = params.get('type'); // 'club' or 'general'
      const offset = Math.max(0, parseInt(params.get('offset') || '0'));
      const limit = Math.min(100, Math.max(1, parseInt(params.get('limit') || '20')));

      // Build dynamic queries based on filter
      let countQuery, dataQuery, countStmt, dataStmt;
      
      if (type && ['club', 'general'].includes(type)) {
        // With type filter
        countQuery = 'SELECT COUNT(*) as total FROM campus_updates WHERE is_published = 1 AND type = ?';
        countStmt = env.DB.prepare(countQuery).bind(type);
        
        dataQuery = `
          SELECT id, type, source, title, content, images, links, date, announcement_date, expires_at
          FROM campus_updates
          WHERE is_published = 1 AND type = ?
          ORDER BY date DESC
          LIMIT ? OFFSET ?
        `;
        dataStmt = env.DB.prepare(dataQuery).bind(type, limit, offset);
      } else {
        // No type filter
        countQuery = 'SELECT COUNT(*) as total FROM campus_updates WHERE is_published = 1';
        countStmt = env.DB.prepare(countQuery);
        
        dataQuery = `
          SELECT id, type, source, title, content, images, links, date, announcement_date, expires_at
          FROM campus_updates
          WHERE is_published = 1
          ORDER BY date DESC
          LIMIT ? OFFSET ?
        `;
        dataStmt = env.DB.prepare(dataQuery).bind(limit, offset);
      }

      // Execute queries
      const { total } = await countStmt.first();
      const { results } = await dataStmt.all();

      // Parse JSON fields for images and links
      const parsedResults = results.map(row => ({
        ...row,
        images: row.images ? JSON.parse(row.images) : [],
        links: row.links ? JSON.parse(row.links) : []
      }));

      // Return with pagination metadata
      return new Response(JSON.stringify({
        data: parsedResults,
        pagination: {
          total: total,
          offset: offset,
          limit: limit,
          count: parsedResults.length,
          hasMore: offset + parsedResults.length < total
        }
      }), {
        headers: {
          ...corsHeaders,
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=60',
          'X-Content-Type-Options': 'nosniff'
        }
      });
    }

    // =========================
    // ADMIN CREATE UPDATE
    // =========================
    if (url.pathname === "/admin/create-update" && request.method === "POST") {
      // Auth check
      const apiKey = request.headers.get("x-api-key");
      
      if (!apiKey || apiKey !== env.ADMIN_KEY) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }

      // Rate limiting for admin endpoint
      if (env.RATE_LIMIT) {
        const allowed = await checkRateLimit(env, clientIP, 'admin');
        if (!allowed) {
          return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
            status: 429,
            headers: {
              ...corsHeaders,
              'Content-Type': 'application/json',
              'Retry-After': '60'
            }
          });
        }
      }

      // Parse and validate request
      let data;
      try {
        const text = await request.text();
        
        // Check request size (max 100KB)
        if (text.length > 100000) {
          return new Response(JSON.stringify({ error: 'Request too large' }), {
            status: 413,
            headers: {
              ...corsHeaders,
              'Content-Type': 'application/json'
            }
          });
        }
        
        data = JSON.parse(text);
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
          status: 400,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }

      // Validate data
      const validationErrors = validateCampusUpdateData(data);
      if (validationErrors.length > 0) {
        return new Response(JSON.stringify({ 
          error: 'Validation failed', 
          details: validationErrors 
        }), {
          status: 400,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }

      // Generate unix timestamp from announcement_date
      const announcementDate = new Date(data.announcement_date);
      const unixTimestamp = Math.floor(announcementDate.getTime() / 1000);

      // Sanitize and prepare data
      const sanitizedData = {
        type: data.type,
        source: data.source ? sanitizeString(data.source) : null,
        title: sanitizeString(data.title),
        content: sanitizeString(data.content),
        images: data.images ? JSON.stringify(data.images) : null,
        links: data.links ? JSON.stringify(data.links) : null,
        date: unixTimestamp,
        announcement_date: data.announcement_date,
        // Auto-set expires_at to 7 days from announcement_date if not provided
        expires_at: data.expires_at || (() => {
          const date = new Date(data.announcement_date);
          date.setDate(date.getDate() + 7);
          return date.toISOString().split('T')[0]; // Format: YYYY-MM-DD
        })(),
        is_published: data.is_published !== undefined ? (data.is_published ? 1 : 0) : 0
      };

      // Insert into database
      try {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO campus_updates
          (type, source, title, content, images, links, date, announcement_date, expires_at, is_published)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          sanitizedData.type,
          sanitizedData.source,
          sanitizedData.title,
          sanitizedData.content,
          sanitizedData.images,
          sanitizedData.links,
          sanitizedData.date,
          sanitizedData.announcement_date,
          sanitizedData.expires_at,
          sanitizedData.is_published
        )
        .run();

        return new Response(JSON.stringify({ 
          success: true,
          message: 'Campus update created',
          data: {
            title: sanitizedData.title,
            date: sanitizedData.date,
            is_published: sanitizedData.is_published === 1
          }
        }), {
          status: 201,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      } catch (error) {
        console.error('Database error:', error);
        return new Response(JSON.stringify({ 
          error: 'Internal server error' 
        }), {
          status: 500,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }
    }

    // =========================
    // ADMIN CREATE
    // =========================
    if (url.pathname === "/admin/create" && request.method === "POST") {
      // Auth check
      const apiKey = request.headers.get("x-api-key");
      
      if (!apiKey || apiKey !== env.ADMIN_KEY) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), {
          status: 401,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }

      // Rate limiting for admin endpoint
      if (env.RATE_LIMIT) {
        const allowed = await checkRateLimit(env, clientIP, 'admin');
        if (!allowed) {
          return new Response(JSON.stringify({ error: 'Rate limit exceeded' }), {
            status: 429,
            headers: {
              ...corsHeaders,
              'Content-Type': 'application/json',
              'Retry-After': '60'
            }
          });
        }
      }

      // Parse and validate request
      let data;
      try {
        const text = await request.text();
        
        // Check request size (max 100KB)
        if (text.length > 100000) {
          return new Response(JSON.stringify({ error: 'Request too large' }), {
            status: 413,
            headers: {
              ...corsHeaders,
              'Content-Type': 'application/json'
            }
          });
        }
        
        data = JSON.parse(text);
      } catch (error) {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
          status: 400,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }

      // Validate data
      const validationErrors = validateAnnouncementData(data);
      if (validationErrors.length > 0) {
        return new Response(JSON.stringify({ 
          error: 'Validation failed', 
          details: validationErrors 
        }), {
          status: 400,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }

      // Sanitize inputs
      const sanitizedData = {
        type: data.type,
        source: data.source,
        title: sanitizeString(data.title),
        content: sanitizeString(data.content),
        link: data.link || null,
        announcement_date: data.announcement_date,
        // Auto-set expires_at to 7 days from announcement_date if not provided
        expires_at: data.expires_at || (() => {
          const date = new Date(data.announcement_date);
          date.setDate(date.getDate() + 7);
          return date.toISOString().split('T')[0]; // Format: YYYY-MM-DD
        })()
      };

      // Insert into database
      try {
        await env.DB.prepare(`
          INSERT OR IGNORE INTO announcements
          (type, source, title, content, link, announcement_date, expires_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `)
        .bind(
          sanitizedData.type,
          sanitizedData.source,
          sanitizedData.title,
          sanitizedData.content,
          sanitizedData.link,
          sanitizedData.announcement_date,
          sanitizedData.expires_at
        )
        .run();

        return new Response(JSON.stringify({ 
          success: true,
          message: 'Announcement created' 
        }), {
          status: 201,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      } catch (error) {
        console.error('Database error:', error);
        return new Response(JSON.stringify({ 
          error: 'Internal server error' 
        }), {
          status: 500,
          headers: {
            ...corsHeaders,
            'Content-Type': 'application/json'
          }
        });
      }
    }

    // Invalid route or method
    return new Response(JSON.stringify({ error: 'Not Found' }), {
      status: 404,
      headers: {
        ...corsHeaders,
        'Content-Type': 'application/json'
      }
    });
  }
};

