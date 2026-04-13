interface CodeAnalysisData {
    native_libraries: Record<string, string[]>;
    native_lib_count: number;
    architectures: string[];
    has_obfuscation: boolean;
    obfuscation_indicators: string[];
}

const CodeAnalysisCard = ({ code }: { code: CodeAnalysisData }) => {
    return (
        <div className="bg-slate-800/50 backdrop-blur-md border border-slate-700 rounded-2xl p-6">
            <h2 className="text-xl font-semibold text-slate-300 mb-4">Code Analysis</h2>

            <div className="space-y-4">
                {/* Obfuscation Status */}
                <div className="flex items-center justify-between pb-3 border-b border-slate-700">
                    <span className="text-slate-400">Code Obfuscation</span>
                    {code.has_obfuscation ? (
                        <span className="px-3 py-1 bg-yellow-500/20 border border-yellow-500/30 rounded-full text-yellow-300 text-xs font-medium">
                            Detected
                        </span>
                    ) : (
                        <span className="px-3 py-1 bg-green-500/20 border border-green-500/30 rounded-full text-green-300 text-xs font-medium">
                            None Detected
                        </span>
                    )}
                </div>

                {/* Native Libraries */}
                {code.native_lib_count > 0 ? (
                    <div>
                        <p className="text-slate-400 text-sm mb-2">
                            Native Libraries ({code.native_lib_count})
                        </p>
                        <div className="space-y-2">
                            {Object.entries(code.native_libraries).map(([arch, libs]) => (
                                <div key={arch} className="bg-slate-700/30 rounded-lg p-3">
                                    <p className="text-cyan-400 font-medium text-sm mb-1">{arch}</p>
                                    <div className="flex flex-wrap gap-1">
                                        {libs.slice(0, 5).map((lib, idx) => (
                                            <span key={idx} className="text-xs text-slate-300 bg-slate-600/30 px-2 py-1 rounded">
                                                {lib}
                                            </span>
                                        ))}
                                        {libs.length > 5 && (
                                            <span className="text-xs text-slate-400 px-2 py-1">
                                                +{libs.length - 5} more
                                            </span>
                                        )}
                                    </div>
                                </div>
                            ))}
                        </div>
                    </div>
                ) : (
                    <div className="flex items-center space-x-2 text-slate-400 text-sm">
                        <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                        </svg>
                        <span>No native libraries detected</span>
                    </div>
                )}

                {/* Architectures */}
                {code.architectures.length > 0 && (
                    <div className="pt-3 border-t border-slate-700">
                        <p className="text-slate-400 text-sm mb-2">Supported Architectures</p>
                        <div className="flex flex-wrap gap-2">
                            {code.architectures.map((arch, idx) => (
                                <span key={idx} className="px-3 py-1 bg-blue-500/20 border border-blue-500/30 rounded-full text-blue-300 text-xs font-medium">
                                    {arch}
                                </span>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
};

export default CodeAnalysisCard;
