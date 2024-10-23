fetch("wasm/addTwo.wasm").then(response =>
    response.arrayBuffer()
  ).then(bytes =>
    WebAssembly.instantiate(bytes, {})
  ).then(result => {
    const addTwo = result.instance.exports.addTwo;
    
    const num1 = Math.floor(Math.random() * 100) + 1;
    const num2 = Math.floor(Math.random() * 100) + 1;

    console.log("wasm.js:", (addTwo(num1, num2)) === (num1 + num2));
  });