/**
 * Data Serialization & Dynamic Parsing Utility
 *
 * Demonstrates insecure deserialization and dynamic code evaluation:
 *  - OWASP A06: Use of known-vulnerable RCE package (node-serialize)
 *  - OWASP A08: Insecure deserialization via serialize.unserialize()
 *  - OWASP A08: Arbitrary code execution via eval()
 */

// ── VULNERABILITY A06: Vulnerable Component / Banned Package ──────────────────
// node-serialize is prone to Remote Code Execution via Immediately Invoked Function Expressions
const serialize = require('node-serialize');

function restoreUserData(req) {
  // ── VULNERABILITY A08: Insecure Deserialization (RCE) ────────────────────────
  // unserialize evaluates embedded executable function code
  const rawPayload = req.body.serializedData;
  const userObject = serialize.unserialize(rawPayload);
  return userObject;
}

function evaluateDynamicFormula(req) {
  // ── VULNERABILITY A08: Arbitrary Code Execution via eval() ────────────────────
  // Evaluating user-supplied expressions executes arbitrary server-side code
  const expression = req.body.calcExpression;
  const result = eval(expression);
  return result;
}

module.exports = {
  restoreUserData,
  evaluateDynamicFormula
};
