interface EntropyData {
    name: string;
    entropy: number;
}

interface EntropyAnalysis {
    dex_entropies: EntropyData[];
    max_entropy: number;
    is_likely_packed: boolean;
    threshold: number;
}

const EntropyCard = ({ analysis }: { analysis: EntropyAnalysis }) => {
    const getEntropyColor = (entropy: number) => {
        if (entropy > 7.2) return 'text-red-400';
        if (entropy > 6.8) return 'text-orange-400';
        return 'text-green-400';
    };

    const getBarColor = (entropy: number) => {
        if (entropy > 7.2) return 'bg-red-500';
        if (entropy > 6.8) return 'bg-orange-500';
        return 'bg-green-500';
    };

    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6">
            <h2 className="text-xl font-semibold text-slate-300 mb-4 flex items-center">
                <svg className="w-5 h-5 mr-2 text-purple-400" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 10V3L4 14h7v7l9-11h-7z" />
                </svg>
                DEX Entropy Analysis
            </h2>

            {analysis.is_likely_packed && (
                <div className="mb-4 p-3 bg-red-500/10 border border-red-500/20 rounded-xl flex items-start space-x-3">
                    <svg className="w-5 h-5 text-red-500 mt-0.5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                    </svg>
                    <div>
                        <p className="text-red-300 text-sm font-medium">Obfuscation / Packing Detected</p>
                        <p className="text-red-400/70 text-xs">High entropy detected in DEX files, suggesting the code may be compressed, encrypted, or packed.</p>
                    </div>
                </div>
            )}

            <div className="space-y-4">
                {analysis.dex_entropies.map((dex, idx) => (
                    <div key={idx}>
                        <div className="flex justify-between mb-1">
                            <span className="text-slate-400 text-sm">{dex.name}</span>
                            <span className={`text-sm font-bold ${getEntropyColor(dex.entropy)}`}>
                                {dex.entropy.toFixed(4)}
                            </span>
                        </div>
                        <div className="w-full bg-slate-700/30 rounded-full h-2 overflow-hidden">
                            <div
                                className={`h-full ${getBarColor(dex.entropy)} transition-all duration-1000`}
                                style={{ width: `${(dex.entropy / 8) * 100}%` }}
                            />
                        </div>
                    </div>
                ))}
            </div>

            <div className="mt-6 grid grid-cols-2 gap-4 pt-4 border-t border-slate-700/50">
                <div>
                    <p className="text-slate-500 text-xs uppercase tracking-wider mb-1">Max Entropy</p>
                    <p className={`text-lg font-bold ${getEntropyColor(analysis.max_entropy)}`}>
                        {analysis.max_entropy.toFixed(4)}
                    </p>
                </div>
                <div>
                    <p className="text-slate-500 text-xs uppercase tracking-wider mb-1">Threshold</p>
                    <p className="text-lg font-bold text-slate-300">{analysis.threshold}</p>
                </div>
            </div>
        </div>
    );
};

export default EntropyCard;
