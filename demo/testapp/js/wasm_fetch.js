WebAssembly.instantiateStreaming(fetch("wasm/addThree.wasm"), {})
    .then(result => {
    const addThree = result.instance.exports.addThree;
    
    const num1 = Math.floor(Math.random() * 100) + 1;
    const num2 = Math.floor(Math.random() * 100) + 1;
    const num3 = Math.floor(Math.random() * 100) + 1;

    console.log("wasm_fetch.js:", (addThree(num1, num2, num3)) === (num1 + num2 + num3));
  });
