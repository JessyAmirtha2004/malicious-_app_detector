import { useState } from 'react';
import AnalysisResult from './AnalysisResult';

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [analysisData, setAnalysisData] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];

      // Validate file extension
      if (!selectedFile.name.endsWith('.apk')) {
        setError('Please select a valid APK file');
        setFile(null);
        return;
      }

      // Validate file size (max 100MB)
      const maxSize = 100 * 1024 * 1024; // 100MB in bytes
      if (selectedFile.size > maxSize) {
        setError('File size exceeds 100MB limit');
        setFile(null);
        return;
      }

      setFile(selectedFile);
      setError(null);
    }
  };

  const handleUpload = async () => {
    if (!file) return;

    setLoading(true);
    setError(null);
    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('http://localhost:3000/upload', {
        method: 'POST',
        body: formData,
      });

      if (!response.ok) {
        throw new Error(`Server error: ${response.status} ${response.statusText}`);
      }

      const data = await response.json();

      if (data.analysis && !data.analysis.error) {
        setAnalysisData(data.analysis);
      } else if (data.analysis && data.analysis.error) {
        setError(`Analysis Error: ${data.analysis.error}`);
      } else {
        setError('Unexpected response format from server');
      }
    } catch (error: any) {
      console.error('Error uploading file:', error);

      if (error.message.includes('Failed to fetch')) {
        setError('Cannot connect to server. Please ensure the backend is running on port 3000.');
      } else {
        setError(error.message || 'Upload failed. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  if (analysisData) {
    return (
      <div className="min-h-screen bg-slate-900 text-white p-8 flex flex-col items-center">
        <button
          onClick={() => { setAnalysisData(null); setFile(null); setError(null); }}
          className="self-start mb-8 flex items-center text-slate-400 hover:text-white transition-colors"
        >
          <svg className="w-5 h-5 mr-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
          </svg>
          Back to Upload
        </button>
        <AnalysisResult data={analysisData} />
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4 relative overflow-hidden bg-slate-900">
      {/* Background blobs */}
      <div className="absolute inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -left-40 w-80 h-80 bg-purple-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob"></div>
        <div className="absolute top-0 -right-40 w-80 h-80 bg-cyan-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-2000"></div>
        <div className="absolute -bottom-40 left-20 w-80 h-80 bg-pink-500 rounded-full mix-blend-multiply filter blur-3xl opacity-20 animate-blob animation-delay-4000"></div>
      </div>

      <div className="relative z-10 max-w-2xl w-full">
        <div className="backdrop-blur-xl bg-white/5 border border-white/10 rounded-2xl shadow-2xl p-8 text-center">
          <h1 className="text-5xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-cyan-400 to-purple-500 mb-4 tracking-tight">
            Mobile Security
          </h1>
          <p className="text-slate-400 mb-10 text-lg">
            Advanced APK Threat Detection & Heuristic Analysis
          </p>

          <div className="border-2 border-dashed border-slate-700 rounded-xl p-16 hover:border-cyan-500/50 hover:bg-slate-800/30 transition-all cursor-pointer group">
            <input
              type="file"
              accept=".apk"
              onChange={handleFileChange}
              className="hidden"
              id="file-upload"
            />
            <label htmlFor="file-upload" className="cursor-pointer flex flex-col items-center w-full h-full">
              <div className="w-20 h-20 bg-slate-800 rounded-full flex items-center justify-center mb-6 group-hover:scale-110 shadow-lg shadow-black/50 transition-transform">
                <svg className="w-10 h-10 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                </svg>
              </div>
              <span className="text-xl font-medium text-slate-200 mb-2">
                {file ? file.name : "Drop APK Here"}
              </span>
              {file && (
                <span className="text-sm text-slate-500 mb-1">
                  {(file.size / (1024 * 1024)).toFixed(2)} MB
                </span>
              )}
              <span className="text-sm text-slate-500">
                AI-Powered Static Analysis
              </span>
            </label>
          </div>

          {/* Error Message */}
          {error && (
            <div className="mt-6 bg-red-500/10 border border-red-500/30 rounded-xl p-4 flex items-start space-x-3">
              <svg className="w-5 h-5 text-red-500 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              <div className="text-left">
                <p className="text-red-300 font-medium text-sm">Error</p>
                <p className="text-red-400/90 text-sm mt-1">{error}</p>
              </div>
            </div>
          )}

          <button
            onClick={handleUpload}
            disabled={!file || loading}
            className={`mt-10 w-full py-4 rounded-xl font-bold text-lg transition-all shadow-lg ${file && !loading
              ? 'bg-gradient-to-r from-cyan-500 to-blue-600 hover:shadow-cyan-500/25 text-white transform hover:-translate-y-1'
              : 'bg-slate-800 text-slate-600 cursor-not-allowed'
              }`}
          >
            {loading ? (
              <span className="flex items-center justify-center">
                <svg className="animate-spin -ml-1 mr-3 h-5 w-5 text-white" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                Analyzing...
              </span>
            ) : "Start Analysis"}
          </button>
        </div>
      </div>
    </div>
  );
}

export default App;
