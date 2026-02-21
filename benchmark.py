import time
import argparse
import json
from scanner import MalwareScanner


def run_benchmark(scan_type='quick', path=None, iterations=3, warmup=1):
    s = MalwareScanner()

    def single_run():
        start = time.perf_counter()
        if scan_type == 'quick':
            res = s.quick_scan()
        elif scan_type == 'full':
            res = s.full_scan()
        elif scan_type == 'custom' and path:
            res = s.custom_scan(path)
        else:
            raise ValueError('Unknown scan type')
        elapsed = time.perf_counter() - start
        return elapsed, res

    # Warmup runs
    for i in range(warmup):
        print(f'Warmup run {i+1}/{warmup} ...')
        _t, _ = single_run()

    times = []
    results = None
    for i in range(iterations):
        print(f'Benchmark run {i+1}/{iterations} ...')
        t, res = single_run()
        times.append(t)
        results = res
        print(f'  Run {i+1} time: {t:.3f}s, files: {len(res)}, infected: {sum(1 for r in res if r.get("status")=="Infected")}')

    print('\nSummary:')
    print('Times:', [f'{t:.3f}s' for t in times])
    print(f'Average: {sum(times)/len(times):.3f}s')
    print(f'Min: {min(times):.3f}s')
    print(f'Max: {max(times):.3f}s')

    # Save last run sample
    try:
        with open('benchmark_last_run.json', 'w') as f:
            json.dump({'times': times, 'sample_results': results[:20]}, f, default=str, indent=2)
        print('Saved sample results to benchmark_last_run.json')
    except Exception as e:
        print('Failed to save sample results:', e)


if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('--scan', choices=['quick', 'full', 'custom'], default='quick')
    p.add_argument('--path', default=None)
    p.add_argument('--iterations', type=int, default=3)
    p.add_argument('--warmup', type=int, default=1)
    args = p.parse_args()

    run_benchmark(scan_type=args.scan, path=args.path, iterations=args.iterations, warmup=args.warmup)
