import { 
    AgChartOptions, 
    AgChartThemeOptions,
    AllCommunityModule,
    ModuleRegistry,
 } from "ag-charts-community";
import { AgCharts } from "ag-charts-react";
ModuleRegistry.registerModules([AllCommunityModule]);

const default_colors = {
    "severity": {
        "secure": {
            "main": "#71717a",
        },
        "low": {
            "main": "#5C85FFff",
        },
        "medium": {
            "main": "#FE9A00ff",
        },
        "high": {
            "main": "#e8175d",
            
        },
        "critical": {
            "main": "#a82424",
        }
    }
};

export default function Donut({
    data,
    colors,
    total,
    totalLabel
}: {
    data: { label: string; count: number, key: string }[];
    colors?: string[];
    total?: number;
    totalLabel?: string;
}) {
    const customDarkTheme: AgChartThemeOptions = {
        // @ts-ignore: The baseTheme property is not officially documented, but it works to extend the material dark theme.
        baseTheme: "ag-material-dark",

        palette: {
            fills: colors || [
                default_colors.severity.critical.main,
                default_colors.severity.high.main,
                default_colors.severity.medium.main,
                default_colors.severity.low.main,
                default_colors.severity.secure.main,
            ],
            strokes: colors || [
                default_colors.severity.critical.main,
                default_colors.severity.high.main,
                default_colors.severity.medium.main,
                default_colors.severity.low.main,
                default_colors.severity.secure.main,
            ],
        },
        overrides: {
            common: {
                background: {
                    fill: "#00000000", // Dark background
                },
                title: {
                    color: "#E8EAED",
                    fontSize: 12,
                    textAlign: "left",
                },
                legend: {
                    spacing: 20,
                    item: {
                        paddingY: 12,
                        paddingX: 20,
                        marker: {
                            size: 12
                        },
                        label: {
                            fontFamily: "'Inter', 'Inter Fallback'",
                            fontSize: 12,
                        },
                    },
                },
            },
        },
    };

    const options: AgChartOptions = {
        data: data,
        theme: customDarkTheme,
        height: 245,
        padding: {
            top: 0,
            bottom: 0,
            left: 0,
            right: 0,
        },
        legend: {
            // maxWidth: 300,
            maxHeight: 100,
            orientation: "horizontal",
            item: {
                marker: {
                    shape: "circle",
                },
                label: {
                    formatter: (params) => {
                        return `${params.value} ${(params.datum.count / total! * 100).toFixed(2)}%`;
                    }
                }
            }
        },
        series: [
            {
                type: "donut",
                calloutLabelKey: "label",
                angleKey: "count",
                calloutLabel: {
                    enabled: false,
                    formatter: (params) => {
                        return `${params.value} (${params.datum.count})`;
                    },
                },
                tooltip: {
                    renderer: ({ datum, fill }) => {
                        return `<div style="font-family: 'Inter', 'Inter Fallback'; font-size: 14px; padding: 8px;">
                            <div style="display: inline-block; content: ''; width: 12px; height: 12px; background: ${fill}; border-radius: 6px; margin-right: 6px; vertical-align: middle;"></div>${datum.label}: ${datum.count}
                        </div>`;
                    }
                },
                
            },
        ],
    };
    return (
        <>
        <div className="chart-total">
            <h3>{total}</h3>
            <div className="chart-total-label">{totalLabel}</div>
        </div>
        <AgCharts options={options} />
        </>
    );
}
