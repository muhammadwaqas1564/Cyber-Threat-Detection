document.getElementById('intrusion-form').addEventListener('submit', async function (event) {

    event.preventDefault();

    const fileInput = document.getElementById('file');
    console.log(fileInput);
    const file = fileInput.files[0];

    if (!file) {
        alert('Please select a file.');
        return;
    }

    const reader = new FileReader();
    reader.onload = async function (event) {
        const data = new Uint8Array(event.target.result);
        const workbook = XLSX.read(data, { type: 'array' });

        // Assuming we want the first sheet
        const firstSheetName = workbook.SheetNames[0];
        const worksheet = workbook.Sheets[firstSheetName];

        // Convert to JSON
        const jsonData = XLSX.utils.sheet_to_json(worksheet);
        try {

            const response = await fetch('http://127.0.0.1:5000/predict/intrusion', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(jsonData[0])
            });
            const result = await response.json();
            
            const resultDiv = document.getElementById('result');
            const color = result.prediction.toLowerCase() === 'benign' ? 'green' : 'red';
            resultDiv.innerHTML = `<h4>Prediction: <span style='color: ${color};'>${result.prediction.toUpperCase()}</span></h4>`;
        } catch (error) {
            alert('An error occured! File may be invalid, Check if it has the same number of features as required!');

        }

    };

    reader.readAsArrayBuffer(file);



});
