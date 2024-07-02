import React, { useState } from 'react';
import { Bar } from 'react-chartjs-2';
import { Chart, registerables } from 'chart.js';
import data from '../data/data.json';
import './Benchmark.css';

Chart.register(...registerables);

const BenchmarkSignatures = () => {
  const [selectedSignature, setSelectedSignature] = useState('');

  const handleSignatureSelect = (signature) => {
    setSelectedSignature(signature);
  };

  return ( 
    <div className="benchmark-chart-container">
      <h1>Signature Benchmark</h1>
        <p>
            The benchmarks were run on a machine with the following specifications:
            <ul>
                <li>Processor: Intel Core i9-9900K</li>
                <li>Memory: 32GB DDR4</li>
                <li>Operating System: Windows 11</li>
            </ul>
        </p>
      <div className="signature-selection">
        <h2>Select Signature</h2>
        <div className="group-buttons">
          {Object.keys(data.sign).map((signature, index) => (
            <button
              key={index}
              className="group-button"
              onClick={() => handleSignatureSelect(signature)}
            >
              {signature}
            </button>
          ))}
        </div>
      </div>
      {selectedSignature && (
        <BenchmarkDisplay selectedSignature={selectedSignature} />
      )}
    </div>
  );
};

const BenchmarkDisplay = ({ selectedSignature }) => {
  const benchmarks = selectedSignature ? data.sign[selectedSignature].benchmarks : {};
  const operations = Object.keys(benchmarks);

  const chartDataTime = {
    labels: Object.keys(benchmarks[operations[0]]),
    datasets: operations.map((operation, index) => ({
      label: operation,
      backgroundColor: `rgba(54, 162, 235, ${index / operations.length})`,
      borderColor: `rgba(54, 162, 235, 1)`,
      borderWidth: 1,
      hoverBackgroundColor: `rgba(54, 162, 235, ${index / operations.length})`,
      hoverBorderColor: `rgba(54, 162, 235, 1)`,
      data: Object.values(benchmarks[operation]).map(item => item.T / item.N * 1e-6)
    }))
  };

  const chartOptionsTime = {
    scales: {
      y: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'Time (ms/op)',
        },
      },
      x: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'N° of keys',
        },
      },
    },
  };

  const chartDataMemory = {
    labels: Object.keys(benchmarks[operations[0]]),
    datasets: operations.map((operation, index) => ({
      label: operation,
      backgroundColor: `rgba(255, 99, 132, ${index / operations.length})`,
      borderColor: `rgba(255, 99, 132, 1)`,
      borderWidth: 1,
      hoverBackgroundColor: `rgba(255, 99, 132, ${index / operations.length})`,
      hoverBorderColor: `rgba(255, 99, 132, 1)`,
      data: Object.values(benchmarks[operation]).map(item => item.MemBytes / item.N * 1e-6)
    }))
  };

  const chartOptionsMemory = {
    scales: {
      y: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'Memory (MB/op)',
        },
      },
      x: {
        beginAtZero: true,
        title: {
          display: true,
          text: 'N° of keys',
        },
      },
    },
  };

  return (
    <div className="benchmark-display">
      <h2>Benchmarks for {selectedSignature}</h2>
      <div className="chart-container">
        <div className="chart">
          <h3>Time</h3>
          <Bar data={chartDataTime} options={chartOptionsTime} />
        </div>
        <div className="chart">
          <h3>Memory</h3>
          <Bar data={chartDataMemory} options={chartOptionsMemory} />
        </div>
      </div>
    </div>
  );
};

export default BenchmarkSignatures;