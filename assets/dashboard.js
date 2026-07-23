(function() {
    function parseJsonAttribute(el, name) {
        try {
            return JSON.parse(el.getAttribute(name) || '[]');
        } catch (e) {
            return [];
        }
    }

    function toRgba(color, alpha) {
        var probe = document.createElement('div');
        probe.style.color = color;
        document.body.appendChild(probe);
        var rgb = getComputedStyle(probe).color;
        document.body.removeChild(probe);
        var match = rgb.match(/\d+/g);
        return match ? 'rgba(' + match[0] + ',' + match[1] + ',' + match[2] + ',' + alpha + ')' : color;
    }

    function buildHourlyChart() {
        var chartEl = document.getElementById('ww-chart-hourly');
        if (!chartEl || typeof Chart === 'undefined') return;

        var root = document.documentElement;
        var cs = getComputedStyle(root);
        var red = cs.getPropertyValue('--pw-error-inline-text-color').trim() || '#c0392b';
        var grid = cs.getPropertyValue('--pw-border-color').trim() || '#444';
        var tickProbe = document.querySelector('.uk-card-header .ww-head') || document.body;
        var tickColor = getComputedStyle(tickProbe).color || '#aaa';

        new Chart(chartEl, {
            type: 'bar',
            data: {
                labels: parseJsonAttribute(chartEl, 'data-labels'),
                datasets: [{
                    data: parseJsonAttribute(chartEl, 'data-values'),
                    backgroundColor: toRgba(red, 0.55),
                    borderColor: red,
                    borderWidth: 1,
                    borderRadius: 3
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: {
                            color: tickColor,
                            font: { size: 9 },
                            maxRotation: 0,
                            callback: function(value, index) {
                                return index % 6 === 0 ? this.getLabelForValue(value) : '';
                            }
                        }
                    },
                    y: {
                        beginAtZero: true,
                        grid: { color: cs.getPropertyValue('--pw-border-color').trim() || grid },
                        ticks: { color: tickColor, font: { size: 9 }, precision: 0 }
                    }
                }
            }
        });
    }

    if (document.readyState === 'complete') {
        requestAnimationFrame(buildHourlyChart);
    } else {
        window.addEventListener('load', function() {
            requestAnimationFrame(buildHourlyChart);
        });
    }
})();
