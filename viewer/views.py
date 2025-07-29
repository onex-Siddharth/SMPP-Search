import csv
import os
from types import SimpleNamespace
from django.shortcuts import render
from django.conf import settings

CSV_PATH = os.path.join(settings.BASE_DIR, 'smpp_full_chains.csv')
import subprocess
import os
from django.http import HttpResponseRedirect,FileResponse, Http404
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages


@csrf_exempt
def generate_csv(request):
    if request.method == 'POST':
        dir_input = request.POST.get('dir_input', '').strip()
        script_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'old.py')

        # Build the command
        cmd = ['python3', script_path]
        if dir_input:
            cmd.append(dir_input)

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            messages.success(request, f"✅ CSV generated successfully!\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messages.error(request, f"❌ Error generating CSV:\n{e.stderr}")
        
        return HttpResponseRedirect(reverse('search_page'))

def search_page(request):
    if request.method == 'POST':
        raw = request.POST.get('query', '').strip()
        # Split into [message_id, port, ip]
        parts = raw.split(';')
        msg_part  = parts[0].strip() if len(parts) > 0 else ''
        port_part = parts[1].strip() if len(parts) > 1 else ''
        ip_part   = parts[2].strip() if len(parts) > 2 else ''

        # Build filters
        msg_ids   = [m.lower() for m in msg_part.split(',') if m] if msg_part else []
        port_filt = port_part or None
        ip_filt   = ip_part   or None

        results = []
        with open(CSV_PATH, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            header = reader.fieldnames
            for row in reader:
                # message_id filter
                mid = row.get('message_id', '').lower()
                if msg_ids and mid not in msg_ids:
                    continue

                # extract submit_src = "ip:port"
                src = row.get('submit_src', '')
                src_ip, src_port = (src.split(':') + ['',''])[:2]

                # port filter
                if port_filt and src_port != port_filt:
                    continue
                # ip filter
                if ip_filt and src_ip != ip_filt:
                    continue

                results.append(SimpleNamespace(**row))

        return render(request, 'search.html', {
            'results': results,
            'header': header,
            'query': raw
        })

    return render(request, 'search.html')


def download_csv(request):
    file_path = 'smpp_full_chains.csv'
    if os.path.exists(file_path):
        return FileResponse(open(file_path, 'rb'), as_attachment=True, filename='smpp_full_chains.csv')
    else:
        raise Http404("CSV file not found.")