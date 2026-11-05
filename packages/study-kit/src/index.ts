// Programmatic entry points (the command line is kya-study, src/cli.ts).
export { main, type Io } from "./main.js";
export { gradePolicy, referenceMandate, SCENARIO, type PolicyGrade, type PolicyResult, type Deviation } from "./policy.js";
export { categorize, ERROR_CATEGORIES, type ErrorCategory } from "./errors.js";
export { buildReport, writeReport, scrub, type StudyReport, type Answers } from "./report.js";
export { compareSnapshots, type ChangeStats } from "./diffstats.js";
export type { Attempt, StudyConfig, TaskId } from "./workspace.js";
