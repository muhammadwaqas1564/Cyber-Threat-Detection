document.getElementById('phishing-form').addEventListener('submit', async function (event) {

    event.preventDefault();

    const urlInput = document.querySelector('input[name="url"]');
    const urlToCheck = urlInput.value;
    try {
        const response = await fetch('/predict/phishing', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: urlToCheck })
        });
        
        const result = await response.json();
        
        const resultDiv = document.getElementById('result');
        const color = result.prediction.toLowerCase() === 'legitimate' ? 'green' : 'red';
        resultDiv.innerHTML = `<h4>URL: ${result.url}<h4>Prediction: <span style='color: ${color};'>${result.prediction.toUpperCase()}</span></h4>`;
    } catch (error) {
        alert('An error occured!');
    }

});
