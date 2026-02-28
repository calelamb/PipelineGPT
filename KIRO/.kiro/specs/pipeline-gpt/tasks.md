# Implementation Plan: PipelineGPT

## Phase 1: Foundation (Hours 0-2)

- [ ] 1. Scaffold Next.js 14 project with TypeScript and Tailwind CSS
  - Run `npx create-next-app@14 pipeline-gpt --typescript --tailwind --app --src-dir`
  - Install dependencies: `npm install reactflow @reactflow/controls @reactflow/background @monaco-editor/react openai ai uuid`
  - Create `.env.local` with `OPENAI_API_KEY=your-key-here`
  - Update `tailwind.config.ts` if needed
  - Verify `npm run dev` works
  - _Requirements: NFR 2, NFR 3_

- [ ] 2. Create all TypeScript type definitions in `src/types/index.ts`
  - Define all pipeline types: StepType, SourceOperation, TransformOperation, DestinationOperation, PipelineOperation, PipelineStepConfig, PipelineStep, PipelineSchedule, PipelineDefinition
  - Define validation types: StepExplanation, StepWarning, ValidationResult
  - Define governance types: UserRole, GovernancePolicy, GovernanceCheck, AuditLogEntry, PipelineTemplate
  - Define chat types: ChatMessage
  - Define UI state types: AppState, PipelineNodeData
  - All types must match the design.md specification exactly
  - _Requirements: 1, 2, 3, 4, 5, 6, 7, 8_

- [ ] 3. Create OpenAI client in `src/lib/openai.ts`
  - Initialize OpenAI client with API key from environment variable
  - Export the client instance
  - _Requirements: 2, 3, 4_

- [ ] 4. Create system prompts in `src/lib/prompts.ts`
  - Write INTENT_PARSE_PROMPT with pipeline architect instructions, Databricks/AWS context, available demo data sources, rules for handling Unity Catalog, Delta Lake, S3, Redshift, Glue
  - Write CODE_GENERATION_PROMPT with Databricks notebook format requirements (# Databricks notebook source, Delta Lake, Unity Catalog, display(), dbutils, S3, Redshift JDBC, Glue, Z-ORDER)
  - Write VALIDATION_PROMPT with plain-English explanation rules and warning severity levels
  - _Requirements: 2, 3, 4_

- [ ] 5. Create OpenAI function calling schemas in `src/lib/functions.ts`
  - Define parsePipelineFunction schema with all operation enums including Databricks/AWS operations, all config properties, dependency tracking
  - Define validatePipelineFunction schema with explanations and warnings arrays
  - _Requirements: 2, 4_

- [ ] 6. Create pipeline-to-nodes utility in `src/lib/pipeline-to-nodes.ts`
  - Implement depth-based layout algorithm for React Flow nodes
  - Map step types to colors (blue/source, amber/transform, green/destination)
  - Map step types to icons (📥/⚙️/📤)
  - Generate edges from dependsOn arrays with animated styling
  - Handle parallel steps at same depth with vertical spacing
  - _Requirements: 8_

**Commit: "feat: add types, OpenAI client, prompts, function schemas, and pipeline-to-nodes utility"**

---

## Phase 2: API Routes (Hours 2-5)

- [ ] 7. Create `/api/parse-intent` route in `src/app/api/parse-intent/route.ts`
  - Accept POST with `{ input: string }`
  - Call OpenAI GPT-5.1 with INTENT_PARSE_PROMPT, parsePipelineFunction, forced tool_choice
  - Parse function call result from response.choices[0].message.tool_calls[0].function.arguments
  - Validate result has at least one source and one destination step
  - Return PipelineDefinition as JSON
  - Handle errors with 500 and { error: message }
  - _Requirements: 2_

- [ ] 8. Create `/api/generate-code` route in `src/app/api/generate-code/route.ts`
  - Accept POST with `{ pipeline: PipelineDefinition }`
  - Call OpenAI GPT-5.1 with CODE_GENERATION_PROMPT, temperature 0.2, no function calling
  - Strip any markdown code fences from response (regex replace)
  - Return `{ code: string }`
  - Handle errors with 500
  - _Requirements: 3_

- [ ] 9. Create `/api/validate` route in `src/app/api/validate/route.ts`
  - Accept POST with `{ pipeline: PipelineDefinition, code: string }`
  - Call OpenAI GPT-5.1 with VALIDATION_PROMPT, validatePipelineFunction, forced tool_choice
  - Parse function call result
  - Return ValidationResult
  - Handle errors with 500
  - _Requirements: 4_

- [ ] 10. Create governance rules engine in `src/lib/governance-rules.ts`
  - Define GOVERNANCE_POLICIES record mapping each UserRole to its GovernancePolicy
  - Define PII_PATTERNS array with regex patterns for common PII column names
  - Implement `runGovernanceChecks(pipeline, role)` function that:
    - Scans all column references for PII patterns
    - Checks operations against role's allowed/blocked lists
    - Checks Unity Catalog references against allowed catalogs/schemas
    - Checks step count against maxSteps
    - Checks for missing schema inference, untyped joins
    - Flags columns that will be auto-masked
  - Returns GovernanceCheck[] array
  - _Requirements: 5, 6_

- [ ] 11. Create `/api/governance-check` route in `src/app/api/governance-check/route.ts`
  - Accept POST with `{ pipeline: PipelineDefinition, role: UserRole }`
  - Call runGovernanceChecks() from governance-rules.ts
  - Determine requiresApproval based on role policy
  - Return `{ checks: GovernanceCheck[], requiresApproval: boolean }`
  - Must return in <100ms (no AI call)
  - _Requirements: 5, NFR 1_

- [ ] 12. Create `/api/refine-pipeline` route in `src/app/api/refine-pipeline/route.ts`
  - Accept POST with `{ existingPipeline: PipelineDefinition, refinement: string }`
  - Call OpenAI GPT-5.1 with INTENT_PARSE_PROMPT + refinement context (include existing pipeline JSON)
  - Use same parsePipelineFunction and forced tool_choice
  - Return updated PipelineDefinition
  - _Requirements: 1_

**Commit: "feat: add all API routes — intent parsing, code generation, validation, governance, refinement"**

---

## Phase 3: Core UI Components (Hours 5-10)

- [ ] 13. Create root layout in `src/app/layout.tsx`
  - Set HTML lang to "en"
  - Set background bg-slate-950, text text-white
  - Set meta title: "PipelineGPT — Natural Language to Databricks Pipelines"
  - Set meta description for Databricks/AWS pipeline generation
  - Use clean system font stack
  - _Requirements: NFR 2_

- [ ] 14. Create custom PipelineNode component in `src/components/PipelineNode.tsx`
  - Render as rounded card with colored left border by step type
  - Show icon (📥/⚙️/📤) and step label
  - Show operation name in smaller text
  - Selected state: glow ring (ring-2 ring-indigo-500/50)
  - Warning state: colored dot in top-right corner
  - Input handle on left (except sources), output handle on right (except destinations)
  - Register as custom React Flow node type
  - _Requirements: 8_

- [ ] 15. Create PipelineDiagram component in `src/components/PipelineDiagram.tsx`
  - Use React Flow to render pipeline as node graph
  - Props: pipeline, validation, selectedStepId, onSelectStep
  - Empty state: "Your pipeline will appear here"
  - Convert pipeline to nodes/edges using pipeline-to-nodes utility
  - Pass validation data into node data for warning indicators
  - Add React Flow controls and subtle dot grid background on bg-slate-900
  - Node click calls onSelectStep, background click deselects
  - _Requirements: 8_

- [ ] 16. Create ChatInterface component in `src/components/ChatInterface.tsx`
  - Props: messages, onSendMessage, isProcessing, templates, onSelectTemplate
  - Scrollable chat window with input bar at bottom
  - User messages: right-aligned, indigo bubble
  - Assistant messages: left-aligned, slate-800 bubble, "◆ PipelineGPT" label
  - Pipeline preview in assistant messages (name, step count, "View Pipeline →")
  - Markdown rendering for assistant messages
  - Single-line input (expands on focus), Enter to send, Shift+Enter for newline
  - Typing indicator (three animated dots) during processing
  - Template cards section when chat is empty
  - Example pills when chat is empty
  - Auto-scroll to latest message
  - _Requirements: 1_

- [ ] 17. Create CodePreview component in `src/components/CodePreview.tsx`
  - Monaco Editor in read-only mode, language: python, theme: vs-dark
  - Props: code, isLoading
  - Empty state: "Generated code will appear here"
  - Loading: pulsing skeleton
  - "Copy Code" button with "Copied!" feedback
  - "Download as .py" button
  - Header: "Generated PySpark — Databricks Notebook" with Databricks icon
  - _Requirements: 3_

- [ ] 18. Create ExplanationPanel component in `src/components/ExplanationPanel.tsx`
  - Props: validation, selectedStepId, pipeline
  - No step selected: show all explanations in order
  - Step selected: highlight that step's explanation at top with warnings
  - Each explanation: step label (bold), type badge (colored), plain-English text, warnings
  - Warning severity styling: yellow/💡 low, orange/⚠️ medium, red/🚨 high
  - Scrollable with max-height
  - _Requirements: 4_

- [ ] 19. Create GovernancePanel component in `src/components/GovernancePanel.tsx`
  - Props: checks, isChecking, role, pipeline
  - Header: "Governance & Compliance" with 🛡️ and overall status badge (green/yellow/red)
  - Check list: status icon (✅/⚠️/❌), rule name, message, expandable details
  - PII Detection section: highlighted box with detected columns and masking status
  - Access Control section: role-specific operation permissions
  - Approval flow: "Approve Pipeline" (admin) or "Submit for Approval" (analyst)
  - Audit Log: collapsible mini trail with timestamps
  - Loading skeleton when isChecking
  - Empty state when no pipeline
  - _Requirements: 5, 6_

- [ ] 20. Create DeployPanel component in `src/components/DeployPanel.tsx`
  - Props: pipeline, code
  - Databricks config: notebook path, cluster dropdown, runtime version
  - AWS config: S3 bucket, IAM role, region dropdown
  - Schedule display (human-readable + cron)
  - Delta Lake output section (if applicable)
  - "Deploy to Databricks" button with 5-step animated simulation
  - Success state: green checkmark, Job ID, paths, locations, "Open in Databricks ↗"
  - _Requirements: 9_

- [ ] 21. Create TemplateLibrary component in `src/components/TemplateLibrary.tsx`
  - Props: templates, onSelectTemplate, isVisible
  - Modal overlay or slide-out panel
  - Header: "Pipeline Templates" + subtitle
  - Category tabs: All, ETL, Analytics, Quality, Reporting
  - Template cards in 2-column grid: icon, name, description, governance badge, step count, "Use Template →"
  - On click: close library, populate chat, auto-send
  - _Requirements: 7_

- [ ] 22. Create RoleToggle component in `src/components/RoleToggle.tsx`
  - Props: currentRole, onRoleChange
  - Segmented control: "👤 Analyst" | "🔧 Admin"
  - Role change triggers governance re-check
  - Visual: admin has purple border, analyst has blue border
  - _Requirements: 6_

- [ ] 23. Create template data in `src/data/templates.ts`
  - Define 6 PipelineTemplate objects: S3 to Delta Lake ETL, Customer 360 View, Data Quality Audit, Weekly Sales Report, Incremental Data Sync, Cross-Source Join
  - Each with: id, name, description, category, icon, defaultPrompt, requiredSources, governanceLevel, steps count
  - _Requirements: 7_

- [ ] 24. Create LoadingSkeleton component in `src/components/LoadingSkeleton.tsx`
  - Reusable animated pulse skeleton (animate-pulse bg-slate-800 rounded)
  - Variants for: pipeline diagram, code panel, explanation panel, governance panel
  - _Requirements: NFR 2_

**Commit: "feat: add all frontend components — chat, diagram, code, governance, templates, roles"**

---

## Phase 4: Main Page Assembly (Hours 10-13)

- [ ] 25. Assemble main page in `src/app/page.tsx`
  - Two-column layout: chat (35%) | results (65%)
  - All state management with React useState (chatMessages, pipeline, code, validation, governance, loading states, role, templates)
  - Wire up message flow: user sends → parse intent → set pipeline → generate code → validate + governance in parallel → update chat
  - Handle refinement flow: existing pipeline + new message → refine → regenerate → revalidate
  - Template selection: populate chat → auto-send → trigger full flow
  - Role toggle: change role → re-run governance
  - Node selection: click diagram node → highlight explanation + governance check
  - Error handling: show errors as red assistant messages
  - Header with logo, tagline, templates button, role toggle, demo button, reset button
  - Footer: "Built at HackUSU 2026 • Data App Factory Track"
  - _Requirements: 1, 2, 3, 4, 5, 6, 7, 8, 9, NFR 2_

**Commit: "feat: assemble main page with full state management and component wiring"**

---

## Phase 5: Demo Mode & Polish (Hours 13-16)

- [ ] 26. Implement Demo mode
  - Auto-send: "Take the sample sales CSV from S3, clean the dates, filter for orders over $100, join with customer data from Unity Catalog, aggregate revenue by region, and write the results to a Delta Lake table partitioned by region"
  - Trigger full build flow automatically
  - After 2s pause, auto-send refinement: "Also add a deduplication step before the join, and mask the customer email column"
  - After refinement completes, switch Analyst → Admin view
  - Start in Analyst view to show restrictions first
  - _Requirements: 10_

- [ ] 27. Implement Reset button
  - Clear all state: chatMessages, pipeline, code, validation, governance
  - Return to empty state with template cards
  - _Requirements: 10_

- [ ] 28. Add loading states and transitions
  - Each panel shows distinct skeleton while loading
  - Pipeline diagram skeleton: faint placeholder nodes
  - Governance panel: scanning animation
  - Fade-in transitions (transition-opacity duration-300)
  - _Requirements: NFR 2_

- [ ] 29. Add UX polish
  - Chat auto-scroll to latest message
  - Node selection scrolls explanation panel to that step
  - Code "Copy" button with green "Copied!" feedback
  - Deploy panel collapsible (default hidden)
  - Empty states for all panels
  - Error handling: errors as red chat messages with retry suggestion
  - _Requirements: 1, 4, 8_

**Commit: "feat: add demo mode, reset, loading states, transitions, and UX polish"**

---

## Phase 6: Final Verification (Hours 16-17)

- [ ] 30. Test core functionality
  - Verify `npm run build` succeeds with zero errors
  - Verify Demo button triggers full flow end-to-end including refinement
  - Verify all 6 templates produce valid pipeline diagrams
  - Verify pipeline diagrams render with correct colors and edges
  - Verify PySpark code starts with "# Databricks notebook source" and uses Delta/Unity Catalog
  - Verify explanations are plain-English with actual column/table names
  - Verify warnings display with correct severity styling
  - _Requirements: 1, 2, 3, 4, 7, 8_

- [ ] 31. Test chat and governance features
  - Verify chat renders user/assistant messages correctly
  - Verify follow-up refinement modifies existing pipeline
  - Verify template selection auto-sends
  - Verify governance panel runs checks after every build
  - Verify PII detection identifies email, phone, salary columns
  - Verify role toggle changes governance results
  - Verify admin shows "Approve", analyst shows "Submit for Approval"
  - Verify audit log shows timestamped entries
  - _Requirements: 1, 5, 6_

- [ ] 32. Test UI polish
  - Verify no console errors in browser
  - Verify all .env.local keys (no hardcoded secrets)
  - Verify app looks polished on 1440px screen
  - Verify deploy panel shows simulated multi-step Databricks deployment
  - _Requirements: NFR 2, NFR 3_

**Commit: "feat: complete Data App Factory MVP — ready for demo"**
