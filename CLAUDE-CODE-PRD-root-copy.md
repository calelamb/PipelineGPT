# Claude Code PRD: International Student Career & Adaptation Platform

## INSTRUCTIONS FOR CLAUDE CODE

You are building a full-stack web application for a hackathon. This document is your complete specification. Build the entire application from scratch, following every section precisely. Do not skip steps. Commit after each major milestone.

---

## PROJECT OVERVIEW

**What:** An AI-powered web platform where international students upload their resume and preferences, get matched with visa-eligible jobs, and chat with a culturally-aware career copilot.

**Tech stack (non-negotiable):**
- Framework: Next.js 14 (App Router, TypeScript)
- Styling: Tailwind CSS
- AI: OpenAI GPT-4 (`gpt-4o` model) with function calling / structured outputs
- Job data: Adzuna API with local JSON fallback
- State: React state only (no database)
- Deployment: Vercel
- Package manager: npm

---

## STEP 1: PROJECT SCAFFOLDING

Run these commands to initialize the project:

```bash
npx create-next-app@latest intl-career-platform --typescript --tailwind --eslint --app --src-dir --import-alias "@/*"
cd intl-career-platform
npm install openai ai react-markdown
npm install -D @types/node
```

Create `.env.local`:
```
OPENAI_API_KEY=your_key_here
ADZUNA_APP_ID=your_id_here
ADZUNA_APP_KEY=your_key_here
```

**Commit: "chore: scaffold Next.js project with dependencies"**

---

## STEP 2: SHARED TYPES

Create `src/types/index.ts`:

```typescript
export interface StudentProfile {
  name: string;
  email: string;
  visaType: "F1_OPT" | "F1_CPT" | "H1B" | "J1" | "OTHER";
  fieldOfStudy: string;
  degreeLevel: "bachelors" | "masters" | "phd";
  skills: string[];
  experienceYears: number;
  languages: string[];
  preferredLocations: string[];
  jobType: "internship" | "fulltime" | "parttime" | "research";
  industries: string[];
  workPreferences: {
    environment: string | null;
    priorities: string | null;
    networkingComfort: string | null;
    biggestConcern: string | null;
    workStyle: string | null;
  };
  education: {
    institution: string;
    degree: string;
    field: string;
    graduationDate: string;
  }[];
  experience: {
    company: string;
    role: string;
    duration: string;
    highlights: string[];
  }[];
}

export interface JobMatch {
  id: string;
  title: string;
  company: string;
  location: string;
  salaryRange: string | null;
  description: string;
  matchScore: number; // 0-100
  visaEligibility: "eligible" | "likely" | "unlikely" | "ineligible";
  explanation: string; // AI-generated plain-English explanation of why this job fits
  sponsorshipHistory: string | null; // e.g., "This company sponsored 47 H-1B visas last year"
  applyUrl: string | null;
}

export interface ChatMessage {
  role: "user" | "assistant";
  content: string;
}

export interface OnboardingFormData {
  resumeText: string; // extracted text from PDF (or pasted)
  visaType: string;
  fieldOfStudy: string;
  degreeLevel: string;
  preferredLocations: string[];
  jobType: string;
  industries: string[];
}
```

**Commit: "feat: add shared TypeScript type definitions"**

---

## STEP 3: STATIC DATA FILES

### 3a. Create `src/data/visa-rules.json`

```json
{
  "F1_OPT": {
    "name": "F-1 Optional Practical Training",
    "maxDuration": "12 months (36 months for STEM extension)",
    "requirements": [
      "Must be directly related to field of study",
      "Must apply within 60 days of program completion",
      "Employer does not need to sponsor (student authorization)",
      "STEM OPT extension requires employer to be E-Verify registered"
    ],
    "restrictions": [
      "Cannot be self-employed (except STEM OPT with certain conditions)",
      "Must report employment to DSO within 10 days",
      "Cannot accumulate more than 90 days of unemployment (150 for STEM OPT)"
    ],
    "workAuthorization": "Student-authorized, no employer sponsorship needed for initial 12 months"
  },
  "F1_CPT": {
    "name": "F-1 Curricular Practical Training",
    "maxDuration": "Varies (part-time or full-time during enrollment)",
    "requirements": [
      "Must be integral part of curriculum (internship, co-op, practicum)",
      "Must have been enrolled full-time for one academic year",
      "Requires authorization from school DSO before starting",
      "Must have a job offer before applying"
    ],
    "restrictions": [
      "12+ months of full-time CPT may make student ineligible for OPT",
      "Must maintain full-time enrollment while on part-time CPT",
      "Employment must be directly related to major"
    ],
    "workAuthorization": "School-authorized, employer does not sponsor"
  },
  "H1B": {
    "name": "H-1B Specialty Occupation",
    "maxDuration": "3 years (extendable to 6 years)",
    "requirements": [
      "Employer must sponsor and file petition",
      "Position must require a bachelor's degree or higher",
      "Subject to annual cap (65,000 + 20,000 master's exemption)",
      "Lottery selection if cap is reached"
    ],
    "restrictions": [
      "Tied to sponsoring employer",
      "Changing employers requires new petition",
      "Cap-gap extension available for F-1 students"
    ],
    "workAuthorization": "Employer-sponsored"
  },
  "J1": {
    "name": "J-1 Exchange Visitor",
    "maxDuration": "Varies by program category",
    "requirements": [
      "Must be sponsored by designated exchange program",
      "Academic training must be related to field of study",
      "Requires approval from program sponsor"
    ],
    "restrictions": [
      "May be subject to two-year home residency requirement",
      "Limited to activities approved by sponsor",
      "Insurance requirements apply"
    ],
    "workAuthorization": "Program-authorized"
  }
}
```

### 3b. Create `src/data/h1b-sponsors.json`

Create a JSON array with at least 50 entries of top H-1B sponsoring companies. Each entry should have:

```json
[
  {
    "company": "Amazon",
    "visasSponsored2024": 15885,
    "approvalRate": 0.94,
    "topRoles": ["Software Development Engineer", "Data Engineer", "Solutions Architect"],
    "locations": ["Seattle, WA", "Arlington, VA", "New York, NY"]
  },
  {
    "company": "Google",
    "visasSponsored2024": 12500,
    "approvalRate": 0.97,
    "topRoles": ["Software Engineer", "Research Scientist", "Product Manager"],
    "locations": ["Mountain View, CA", "New York, NY", "Seattle, WA"]
  },
  {
    "company": "Microsoft",
    "visasSponsored2024": 10800,
    "approvalRate": 0.96,
    "topRoles": ["Software Engineer", "Program Manager", "Data Scientist"],
    "locations": ["Redmond, WA", "New York, NY", "Atlanta, GA"]
  },
  {
    "company": "Meta",
    "visasSponsored2024": 8500,
    "approvalRate": 0.95,
    "topRoles": ["Software Engineer", "Research Scientist", "Production Engineer"],
    "locations": ["Menlo Park, CA", "New York, NY", "Seattle, WA"]
  },
  {
    "company": "Apple",
    "visasSponsored2024": 7200,
    "approvalRate": 0.96,
    "topRoles": ["Software Engineer", "ML Engineer", "Hardware Engineer"],
    "locations": ["Cupertino, CA", "Austin, TX", "Seattle, WA"]
  }
]
```

Populate with at least 50 real companies using publicly available DOL H-1B disclosure data. Include a mix of big tech, consulting firms (Deloitte, Accenture, Infosys, TCS, Wipro, Cognizant), finance (Goldman Sachs, JPMorgan, Citi), healthcare, and mid-size tech companies. Use realistic numbers.

### 3c. Create `src/data/jobs-fallback.json`

Create a JSON array of 100+ realistic job postings. Each entry:

```json
[
  {
    "id": "job_001",
    "title": "Software Engineer - New Grad",
    "company": "Amazon",
    "location": "Seattle, WA",
    "salaryRange": "$120,000 - $160,000",
    "description": "Design and build scalable distributed systems. Work with a team of engineers to develop new features for AWS services.",
    "requirements": ["Bachelor's in CS or related field", "Experience with Java, Python, or C++", "Understanding of data structures and algorithms"],
    "jobType": "fulltime",
    "industry": "technology",
    "sponsorship": true,
    "applyUrl": "https://amazon.jobs/example",
    "postedDate": "2026-02-15"
  }
]
```

Include diverse jobs across: technology, finance, consulting, healthcare, research, engineering. Mix of internships and full-time roles. Some should have `"sponsorship": true`, others `false`. Make them realistic — use real company names and plausible descriptions.

**Commit: "feat: add static visa rules, H-1B sponsor data, and fallback job listings"**

---

## STEP 4: OPENAI UTILITY + PROMPTS

### 4a. Create `src/lib/openai.ts`

```typescript
import OpenAI from "openai";

export const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});
```

### 4b. Create `src/lib/prompts.ts`

This file contains all system prompts. These are critical — the quality of the AI experience depends on these.

```typescript
export const RESUME_PARSE_PROMPT = `You are a resume parsing engine for international students in the United States. Given the text content of a resume, extract structured information accurately.

Rules:
- Extract all education entries with institution, degree, field, and graduation date
- Extract all work experience with company, role, duration, and key highlights
- Identify technical and soft skills
- Infer the candidate's likely visa needs based on education (e.g., if studying at a US university, likely F-1)
- Identify languages spoken
- Be thorough — don't miss skills listed in project descriptions or coursework
- If information is ambiguous or missing, use null rather than guessing`;

export const JOB_MATCHING_PROMPT = `You are a job matching engine specialized in helping international students in the US find visa-eligible employment.

You will receive:
1. A student profile (education, skills, visa status, preferences)
2. A list of job postings

For each job, evaluate and score:
- Skill match (does the student's background align with requirements?)
- Visa eligibility (based on the student's visa type, is this job legally accessible?)
- Career fit (does it align with their field of study, interests, and preferences?)

Visa eligibility rules:
- F-1 OPT: Job must be related to field of study. No employer sponsorship needed for first 12 months. STEM OPT extension requires E-Verify employer.
- F-1 CPT: Must be part of curriculum. Typically internships.
- H-1B: Employer must be willing to sponsor. Check against known sponsor list.
- J-1: Must align with exchange program category.

For each job, provide:
- matchScore: 0-100 integer
- visaEligibility: "eligible", "likely", "unlikely", or "ineligible"
- explanation: 2-3 sentences explaining WHY this job is a good/bad fit, written for the student (not a recruiter). Be specific about visa implications.
- sponsorshipHistory: If the company is a known H-1B sponsor, mention how many visas they sponsored.

Return the top matches sorted by matchScore descending. Only return jobs where matchScore > 30.`;

export const COPILOT_SYSTEM_PROMPT = `You are a career and cultural adaptation advisor for international students in the United States. You provide personalized, actionable guidance.

Your knowledge includes:
- US workplace culture and professional norms
- Visa regulations (F-1 OPT, CPT, H-1B, J-1, and related processes)
- Resume and cover letter conventions for US employers
- Interview preparation and behavioral question frameworks
- Networking etiquette (career fairs, LinkedIn, cold outreach, informational interviews)
- Salary negotiation norms in the US
- Cultural differences that commonly affect students from East Asia, South Asia, and other regions

Your personality:
- Warm, encouraging, and direct
- You give specific, actionable advice (not vague platitudes)
- You understand the stress and isolation international students face
- You proactively mention visa implications when relevant
- You use concrete examples and scripts the student can use verbatim

You will be given the student's profile. Use it to personalize every response. Reference their specific field, visa type, and preferences. Never give generic advice when you have specific context.

If the student asks something outside your expertise (legal advice, medical questions, etc.), clearly say so and suggest appropriate resources (e.g., "Talk to your DSO about this" or "Consult an immigration attorney").

If this is the beginning of the conversation, introduce yourself briefly and ask the student what they'd like help with. Suggest 3-4 things you can help with based on their profile.`;
```

### 4c. Create `src/lib/functions.ts`

Define the OpenAI function calling schemas:

```typescript
export const parseResumeFunction = {
  name: "extract_student_profile",
  description: "Extract structured student profile data from resume text",
  parameters: {
    type: "object" as const,
    properties: {
      name: { type: "string", description: "Student's full name" },
      email: { type: "string", description: "Email address if present" },
      education: {
        type: "array",
        items: {
          type: "object",
          properties: {
            institution: { type: "string" },
            degree: { type: "string", description: "e.g., Bachelor of Science, Master of Engineering" },
            field: { type: "string", description: "Field of study / major" },
            graduationDate: { type: "string", description: "Expected or actual graduation date" },
          },
          required: ["institution", "degree", "field"],
        },
      },
      experience: {
        type: "array",
        items: {
          type: "object",
          properties: {
            company: { type: "string" },
            role: { type: "string" },
            duration: { type: "string" },
            highlights: {
              type: "array",
              items: { type: "string" },
              description: "Key accomplishments or responsibilities",
            },
          },
          required: ["company", "role"],
        },
      },
      skills: {
        type: "array",
        items: { type: "string" },
        description: "All technical and soft skills mentioned",
      },
      languages: {
        type: "array",
        items: { type: "string" },
        description: "Languages the student speaks",
      },
      experienceYears: {
        type: "number",
        description: "Estimated total years of professional experience",
      },
    },
    required: ["name", "education", "skills"],
  },
};

export const matchJobsFunction = {
  name: "rank_job_matches",
  description: "Score and rank job postings for a student",
  parameters: {
    type: "object" as const,
    properties: {
      matches: {
        type: "array",
        items: {
          type: "object",
          properties: {
            jobId: { type: "string" },
            matchScore: { type: "number", description: "0-100 match score" },
            visaEligibility: {
              type: "string",
              enum: ["eligible", "likely", "unlikely", "ineligible"],
            },
            explanation: { type: "string", description: "2-3 sentence explanation for the student" },
            sponsorshipHistory: { type: "string", description: "H-1B sponsorship info if available, null otherwise" },
          },
          required: ["jobId", "matchScore", "visaEligibility", "explanation"],
        },
      },
    },
    required: ["matches"],
  },
};
```

**Commit: "feat: add OpenAI client, system prompts, and function calling schemas"**

---

## STEP 5: API ROUTES

### 5a. Create `src/app/api/parse-resume/route.ts`

This route:
1. Accepts POST with `{ resumeText: string }`
2. Calls OpenAI GPT-4 with the resume parse system prompt and function calling schema
3. Returns the structured `StudentProfile` (partial — without visa type and preferences, which come from the form)

Handle errors gracefully. If parsing fails, return a 500 with a readable error message.

### 5b. Create `src/app/api/match-jobs/route.ts`

This route:
1. Accepts POST with `{ profile: StudentProfile }`
2. Loads jobs from Adzuna API first, falling back to `jobs-fallback.json` if the API fails or returns no results
3. Loads `h1b-sponsors.json` to enrich sponsorship data
4. Calls OpenAI GPT-4 with the job matching system prompt, function calling schema, the student profile, and the job list
5. Returns an array of `JobMatch` objects sorted by matchScore

For the Adzuna API call:
- Base URL: `https://api.adzuna.com/v1/api/jobs/us/search/1`
- Query params: `app_id`, `app_key`, `what` (skills/field), `where` (preferred location), `results_per_page=50`
- Parse the response and normalize to your job format
- If the API call fails for any reason, fall back to the static JSON file silently

### 5c. Create `src/app/api/copilot/route.ts`

This route:
1. Accepts POST with `{ messages: ChatMessage[], profile: StudentProfile }`
2. Constructs the system prompt by combining `COPILOT_SYSTEM_PROMPT` with the student's profile data (serialize the profile into the system message so the copilot has full context)
3. Calls OpenAI GPT-4 chat completions (NOT function calling — this is a standard chat)
4. Streams the response back to the client using the Vercel AI SDK's `StreamingTextResponse` or manual SSE

Use streaming for the copilot so the user sees tokens appear in real time. This is important for UX.

**Commit: "feat: add API routes for resume parsing, job matching, and copilot chat"**

---

## STEP 6: FRONTEND COMPONENTS

### Design System

Use Tailwind CSS with a clean, professional color scheme:
- Primary: indigo-600 (`#4F46E5`)
- Background: slate-50 (`#F8FAFC`)
- Cards: white with subtle shadow (`shadow-sm border border-slate-200`)
- Text: slate-900 for headings, slate-600 for body
- Accents: green for "eligible", yellow for "likely", red for "ineligible"
- Rounded corners on everything (`rounded-xl` for cards, `rounded-lg` for buttons)

The overall aesthetic should feel modern, clean, and trustworthy. Think Linear or Notion, not Bootstrap.

### 6a. Create `src/components/ResumeUpload.tsx`

A component that:
- Has a large drag-and-drop zone for PDF files
- Also has a "paste your resume text" textarea as an alternative
- On file drop, extracts text from the PDF client-side (use `pdf.js` or just send the raw text — for hackathon MVP, the textarea paste is fine)
- Shows a loading state while processing
- On success, displays a confirmation with the extracted name and skill count

### 6b. Create `src/components/OnboardingForm.tsx`

A multi-step form (or single scrolling form) that collects:
1. Resume (via ResumeUpload component)
2. Visa type (dropdown: F-1 OPT, F-1 CPT, H-1B, J-1, Other)
3. Field of study (text input)
4. Degree level (dropdown: Bachelor's, Master's, PhD)
5. Preferred locations (multi-select or comma-separated text input)
6. Job type (dropdown: Internship, Full-time, Part-time, Research)
7. Industries of interest (multi-select checkboxes: Technology, Finance, Consulting, Healthcare, Research, Education, Other)

Include a "Find My Matches" submit button at the bottom. On submit:
1. Call `/api/parse-resume` with the resume text
2. Merge the parsed data with the form data to create a complete `StudentProfile`
3. Store the profile in React state (lifted to the parent page)
4. Navigate to the dashboard view

### 6c. Create `src/components/JobCard.tsx`

A card component displaying one job match:
- Job title (large, bold)
- Company name
- Location
- Salary range (if available)
- Match score displayed as a colored circular badge (green > 70, yellow > 40, red otherwise)
- Visa eligibility badge:
  - "Eligible" = green badge with checkmark
  - "Likely" = yellow badge
  - "Unlikely" = orange badge
  - "Ineligible" = red badge with X
- AI explanation text (the 2-3 sentence explanation)
- Sponsorship history line (if available, e.g., "Amazon sponsored 15,885 H-1B visas in 2024")
- "Apply" button (links to applyUrl or shows "URL not available")

### 6d. Create `src/components/JobDashboard.tsx`

The main dashboard view:
- Header showing student name and profile summary (visa type, field, location prefs)
- Filter bar: filter by visa eligibility, sort by match score or company name
- Grid or list of JobCard components
- Loading skeleton while jobs are being matched
- Empty state if no matches found: "No matches found. Try broadening your location preferences or checking a different job type."
- Count indicator: "Showing 15 visa-eligible matches"

### 6e. Create `src/components/ChatInterface.tsx`

A chat interface for the copilot:
- Message list (scrollable, auto-scrolls to bottom on new message)
- User messages aligned right (indigo background, white text)
- Assistant messages aligned left (white background, slate text)
- Support markdown rendering in assistant messages (use `react-markdown`)
- Text input at the bottom with send button
- Show typing indicator while streaming
- On mount (first open), automatically send an empty first message to trigger the copilot's introduction
- Store conversation history in React state

### 6f. Create `src/components/Navigation.tsx`

A simple top nav or sidebar with three sections:
- "Profile" (onboarding/edit profile)
- "Job Matches" (dashboard)
- "Career Copilot" (chat)

Use tab-style navigation or a sidebar. Highlight the active section.

**Commit: "feat: add all frontend components"**

---

## STEP 7: PAGE ASSEMBLY

### 7a. Create `src/app/page.tsx` (Landing / Onboarding)

The main entry point:
- If no profile exists in state: show the OnboardingForm
- If profile exists: show the Navigation + active view (default to JobDashboard)
- Lift the `StudentProfile` state here and pass it down to child components
- Also lift the `jobMatches` state here

Flow:
1. User lands on page → sees OnboardingForm
2. Completes form → profile is created → automatically calls `/api/match-jobs`
3. Redirected to dashboard with job results loading
4. Can navigate between Dashboard and Copilot via Navigation

### 7b. Create the layout in `src/app/layout.tsx`

- Clean layout with the app name in the header
- Use a placeholder name like "GlobalCareer AI" or similar
- Footer with "Built at HackUSU 2026"

**Commit: "feat: assemble pages and wire up navigation + state management"**

---

## STEP 8: POLISH & UX

1. Add loading skeletons for the job dashboard (animated pulse placeholders)
2. Add error boundaries — if an API call fails, show a friendly error message, not a crash
3. Add transition animations between onboarding → dashboard (subtle fade)
4. Make the layout responsive (works on laptop screens, which is what judges will see)
5. Add a "Start Over" button that clears the profile and returns to onboarding
6. Add sample/demo data: include a "Try Demo" button on the onboarding page that auto-fills with a sample international student profile so judges can skip the form during the demo
7. Ensure the copilot's first message is welcoming and references the student's actual profile data

**Commit: "feat: add loading states, error handling, and demo mode"**

---

## STEP 9: FINAL CHECKS

Before declaring done, verify:

- [ ] Full flow works: Onboarding → Resume parse → Job matching → Dashboard → Copilot
- [ ] The "Try Demo" button fills in sample data and completes the flow without manual input
- [ ] Job cards display visa eligibility badges correctly
- [ ] Copilot responds with personalized advice referencing the student's profile
- [ ] No TypeScript errors (`npm run build` succeeds)
- [ ] Responsive layout (no horizontal scroll on standard laptop)
- [ ] Loading states display during API calls
- [ ] Error states display when API calls fail
- [ ] All environment variables are referenced from `.env.local` (no hardcoded keys)

**Final commit: "feat: complete MVP — ready for demo"**

---

## API REFERENCE

### OpenAI

Model: `gpt-4o`

For function calling (resume parse, job matching):
```typescript
const response = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [...],
  tools: [{
    type: "function",
    function: parseFunctionDefinition
  }],
  tool_choice: { type: "function", function: { name: "function_name" } }
});

// Extract the function call result:
const result = JSON.parse(response.choices[0].message.tool_calls[0].function.arguments);
```

For chat (copilot):
```typescript
const response = await openai.chat.completions.create({
  model: "gpt-4o",
  messages: [
    { role: "system", content: systemPrompt },
    ...conversationHistory
  ],
  stream: true
});
```

### Adzuna API

```
GET https://api.adzuna.com/v1/api/jobs/us/search/1?app_id={ID}&app_key={KEY}&what={keywords}&where={location}&results_per_page=50
```

Response shape:
```json
{
  "results": [
    {
      "id": "string",
      "title": "string",
      "company": { "display_name": "string" },
      "location": { "display_name": "string" },
      "description": "string",
      "salary_min": number,
      "salary_max": number,
      "redirect_url": "string",
      "created": "string"
    }
  ]
}
```

---

## FILE STRUCTURE (FINAL)

```
src/
├── app/
│   ├── page.tsx                     # Main page (onboarding → dashboard)
│   ├── layout.tsx                   # Root layout
│   ├── globals.css                  # Tailwind imports
│   └── api/
│       ├── parse-resume/
│       │   └── route.ts             # Resume → structured profile
│       ├── match-jobs/
│       │   └── route.ts             # Profile → ranked job matches
│       └── copilot/
│           └── route.ts             # Chat with career copilot
├── components/
│   ├── ResumeUpload.tsx             # Drag-drop / paste resume
│   ├── OnboardingForm.tsx           # Multi-field intake form
│   ├── JobCard.tsx                  # Single job match card
│   ├── JobDashboard.tsx             # Grid of job cards + filters
│   ├── ChatInterface.tsx            # Copilot chat UI
│   └── Navigation.tsx               # Tab nav between views
├── lib/
│   ├── openai.ts                    # OpenAI client
│   ├── prompts.ts                   # All system prompts
│   └── functions.ts                 # Function calling schemas
├── types/
│   └── index.ts                     # Shared TypeScript types
└── data/
    ├── visa-rules.json              # Visa type rules reference
    ├── h1b-sponsors.json            # Top H-1B sponsoring companies
    └── jobs-fallback.json           # Fallback job listings
```

---

## IMPORTANT CONSTRAINTS

- Do NOT add authentication. Fake a logged-in state.
- Do NOT use a database. All state lives in React useState/useContext.
- Do NOT spend time on deployment config beyond basic Vercel.
- Do NOT add multi-language support (English only).
- Do NOT attempt to parse PDF files on the server — use client-side text extraction or just support paste-in text for the MVP.
- DO make the UI look polished. This is a hackathon — visual impression matters.
- DO add the "Try Demo" button — judges need to see the full flow in under 2 minutes.
- DO use streaming for the copilot chat — it feels dramatically better than waiting for a full response.
- DO commit after each major step with descriptive messages. Judges check commit history.
