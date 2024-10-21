function testEvalCSP() {
  try {
    eval('console.log("Eval is not blocked by CSP");');
    console.error("Eval executed successfully");
  } catch (error) {
    if (error instanceof EvalError || error.message.includes('Content Security Policy')) {
      console.log("csp.js", true);
    } else {
      console.error("Eval failed with another error:", error.message);
    }
  }
}

// Run the test
testEvalCSP();
