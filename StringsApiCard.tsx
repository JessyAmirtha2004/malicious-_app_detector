interface StringsApiData {
    suspicious_strings: string[];
    suspicious_string_count: number;
    high_risk_apis: string[];
    api_misuse_count: number;
}

const StringsApiCard = ({ data }: { data: StringsApiData }) => {
    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6">
            <h2 className="text-xl font-semibold text-slate-300 mb-6 flex items-center">
                <svg className="w-5 h-5 mr-2 text-yellow-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 20l4-16m4 4l4 4-4 4M6 16l-4-4 4-4" />
                </svg>
                Code Characteristics
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {/* Suspicious Strings */}
                <div>
                    <div className="flex items-center justify-between mb-3">
                        <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider">Suspicious Strings</h3>
                        <span className="bg-yellow-500/20 text-yellow-400 px-2 py-0.5 rounded text-xs font-bold">
                            {data.suspicious_string_count} Found
                        </span>
                    </div>
                    {data.suspicious_strings.length > 0 ? (
                        <div className="space-y-2 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
                            {data.suspicious_strings.map((str, idx) => (
                                <div key={idx} className="bg-slate-900/50 p-2 rounded border border-slate-800 text-xs font-mono text-yellow-200/80 break-all">
                                    {str}
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="text-slate-500 text-sm italic py-4">No suspicious strings patterns matched.</div>
                    )}
                </div>

                {/* High Risk APIs */}
                <div>
                    <div className="flex items-center justify-between mb-3">
                        <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider">High-Risk APIs</h3>
                        <span className="bg-red-500/20 text-red-400 px-2 py-0.5 rounded text-xs font-bold">
                            {data.api_misuse_count} Found
                        </span>
                    </div>
                    {data.high_risk_apis.length > 0 ? (
                        <div className="space-y-2 max-h-48 overflow-y-auto pr-2 custom-scrollbar">
                            {data.high_risk_apis.map((api, idx) => (
                                <div key={idx} className="bg-slate-900/50 p-2 rounded border border-slate-800 text-xs font-mono text-red-200/80 break-all">
                                    {api.split(';').pop()?.replace('->', '.')}
                                </div>
                            ))}
                        </div>
                    ) : (
                        <div className="text-slate-500 text-sm italic py-4">No high-risk API usage patterns matched.</div>
                    )}
                </div>
            </div>

            {(data.suspicious_string_count > 0 || data.api_misuse_count > 0) && (
                <div className="mt-6 p-3 bg-red-500/5 border border-red-500/10 rounded-xl">
                    <p className="text-[10px] text-slate-500 leading-tight">
                        <span className="text-red-400 font-bold mr-1">NOTE:</span>
                        Detection of suspicious strings or API patterns does not definitively mean the app is malicious, but it warrants manual investigation of those code segments.
                    </p>
                </div>
            )}
        </div>
    );
};

export default StringsApiCard;
