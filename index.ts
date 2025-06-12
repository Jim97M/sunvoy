import "dotenv/config";
import axios from "axios";
import * as cheerio from "cheerio";
import fs from "fs";
import crypto from "crypto";

const LOGIN_URL = process.env.LOGIN_URL!;
const USERS_ENDPOINT = process.env.USERS_LIST!;
const USER_EMAIL = process.env.USER_EMAIL!;
const USER_PASSWORD = process.env.USER_PASSWORD!;

const TOKEN_PAGE_URL = process.env.TOKEN_PAGE!;

let sessionCookies = ""; 

interface UserProfile {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
}

interface TokenData {
  access_token: string;
  openId: string;
  userId: string;
  apiuser: string;
  operateId: string;
  language: string;
}


const httpClient: any = axios.create({
  withCredentials: true,
  maxRedirects: 0,
  validateStatus: status => status === 200 || status === 302,
});

async function loginUser(): Promise<string | undefined> {
  try {
    const response = await httpClient.get(LOGIN_URL);
    
    if (response.headers['set-cookie']) {
      sessionCookies = response.headers['set-cookie']
        .map(c => c.split(';')[0])
        .join('; ');
    }
    
    const $ = cheerio.load(response.data);
    return $('input[name=nonce]').val()?.toString();
  } catch (err) {
    console.warn("Failed getting nonce:", err);
    return undefined;
  }
}

async function performLogin(nonce?: string): Promise<void> {
  const params = new URLSearchParams();
  params.append('username', USER_EMAIL);
  params.append('password', USER_PASSWORD);
  if (nonce) params.append('nonce', nonce);

  try {
    const res = await httpClient.post(LOGIN_URL, params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer': LOGIN_URL,
        'Cookie': sessionCookies,
      },
    });

    if (res.status === 302 && res.headers.location === '/list') {
      if (res.headers['set-cookie']) {
        const newCookies = res.headers['set-cookie'].map(c => c.split(';')[0]).join('; ');
        sessionCookies = sessionCookies 
          ? `${sessionCookies}; ${newCookies}` 
          : newCookies;
      }
      console.log('✓ Login successful!');
    } else {
      throw new Error(`Unexpected response: ${res.status}`);
    }
  } catch (error) {
    console.error('!! Login failed:', error);
    throw error; 
  }
}


async function saveUserList(): Promise<void> {
  try {
    const response = await httpClient.post(USERS_ENDPOINT, null, {
      headers: { Cookie: sessionCookies },
    });

    const users: UserProfile[] = response.data;
    fs.writeFileSync('users.json', JSON.stringify({ users }, null, 2));
    console.log("Saved user list");
  } catch (err) {
    console.error("Couldn't save users:", err);
  }
}

function parseTokenSettings(html: string): TokenData {
  const $ = cheerio.load(html);
  return {
    access_token: $('#access_token').val() as string,
    openId: $('#openId').val() as string,
    userId: $('#userId').val() as string,
    apiuser: $('#apiuser').val() as string,
    operateId: $('#operateId').val() as string,
    language: $('#language').val() as string,
  };
}

// Generate security checkcode
function createCheckcode(
  apiuser: string,
  access_token: string,
  openId: string,
  operateId: string,
  timestamp: string,
  userId: string
): string {
  const raw = [apiuser, access_token, openId, operateId, timestamp, userId]
    .map(p => (p || '').trim())
    .join('');
  
  return crypto
    .createHmac('sha1', access_token)
    .update(raw)
    .digest('hex')
    .toUpperCase();
}

// Get CSRF token from cookies
function getCsrfToken(cookies: string): string | undefined {
  const match = cookies.split('; ').find(c => c.startsWith('_csrf_token='));
  return match?.split('=')[1];
}

// Fetch token settings from protected page
async function retrieveTokenSettings(): Promise<TokenData> {
  const res = await httpClient.get(TOKEN_PAGE_URL, {
    headers: { Cookie: sessionCookies },
  });
  return parseTokenSettings(res.data);
}




(async function main() {
  try {
    console.log("Starting script...");
    
    const doesOn = await loginUser();
    await performLogin(doesOn);
    await retrieveTokenSettings();
    await saveUserList();
    
  } catch (err) {
    console.error("!! Critical failure:", err);
    process.exit(1);
  }
})();
