import "dotenv/config";
import axios from "axios";
import * as cheerio from "cheerio";
import fs from "fs";

const LOGIN_URL = process.env.LOGIN_URL!;
const USERS_ENDPOINT = process.env.USERS_LIST!;
const USER_EMAIL = process.env.USER_EMAIL!;
const USER_PASSWORD = process.env.USER_PASSWORD!;

let sessionCookies = ""; 

interface UserProfile {
  id: string;
  firstName: string;
  lastName: string;
  email: string;
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

// Main login function
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

    // Handle successful login
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
    throw error;  // Re-throw for caller
  }
}


// Save user list to file
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


(async function main() {
  try {
    console.log("Starting script...");
    
    const doesOn = await loginUser();
    await performLogin(doesOn);

    await saveUserList();
    
  } catch (err) {
    console.error("!! Critical failure:", err);
    process.exit(1);
  }
})();
