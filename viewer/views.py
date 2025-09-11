import csv
import os
import subprocess
from types import SimpleNamespace
from django.shortcuts import render
from django.conf import settings
from django.http import HttpResponseRedirect, FileResponse, Http404
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.contrib import messages

BASE_DIR             = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CSV_PATH             = os.path.join(BASE_DIR, 'smpp_full_chains.csv')
SOCKET_SUMMARY_PATH  = os.path.join(BASE_DIR, 'socket_summary.csv')
SOCKET_CSV_DIR       = os.path.join(BASE_DIR, 'socket_csvs')


@csrf_exempt
def generate_csv(request):
    if request.method == 'POST':
        dir_input   = request.POST.get('dir_input', '').strip()
        script_path = os.path.join(BASE_DIR, 'old.py')
        cmd         = ['python3', script_path]

        if dir_input:
            cmd.append(dir_input)
        else:
            # Default: use uploaded_pcaps folder
            upload_dir = os.path.join(BASE_DIR, 'uploaded_pcaps')
            os.makedirs(upload_dir, exist_ok=True)
            cmd.append(upload_dir)

        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            messages.success(request, f" CSV generated successfully!\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messages.error(request, f" Error generating CSV:\n{e.stderr}")

        return HttpResponseRedirect('/?generated=1')

    return HttpResponseRedirect(reverse('search_page'))



def search_page(request):
    # Show socket summary only if we have ?generated=1
    show_summary = request.GET.get('generated') == '1'

    results      = []
    socket_stats = []
    header       = []
    raw          = ""

    # Handle your POST search
    if request.method == 'POST':
        raw   = request.POST.get('query', '').strip()
        parts = raw.split(';')
        msg_part  = parts[0].strip() if len(parts) > 0 else ''
        port_part = parts[1].strip() if len(parts) > 1 else ''
        ip_part   = parts[2].strip() if len(parts) > 2 else ''

        msg_ids   = [m.lower() for m in msg_part.split(',') if m] if msg_part else []
        port_filt = port_part or None
        ip_filt   = ip_part   or None

        with open(CSV_PATH, newline='') as csvfile:
            reader = csv.DictReader(csvfile)
            header = reader.fieldnames
            for row in reader:
                mid = row.get('message_id','').lower()
                if msg_ids and mid not in msg_ids:
                    continue

                src = row.get('submit_src','')
                src_ip, src_port = (src.split(':') + ['',''])[:2]
                if port_filt and src_port != port_filt:
                    continue
                if ip_filt   and src_ip   != ip_filt:
                    continue

                results.append(SimpleNamespace(**row))

    # Always load socket_stats (but template will check show_summary)
    try:
        with open(SOCKET_SUMMARY_PATH, newline='') as f:
            reader = csv.DictReader(f)
            for row in reader:
                src = row['submit_src']
                dst = row['submit_dst']
                filename = f"chains_{src.replace(':','_')}__{dst.replace(':','_')}.csv"
                socket_stats.append({
                    **row,
                    'download_link': f"/download/socket/{filename}/"
                })
    except FileNotFoundError:
        socket_stats = []

    return render(request, 'search.html', {
        'results'     : results,
        'header'      : header,
        'query'       : raw,
        'socket_stats': socket_stats,
        'show_summary': show_summary,
    })


def download_csv(request):
    if os.path.exists(CSV_PATH):
        return FileResponse(open(CSV_PATH,'rb'),
                             as_attachment=True,
                             filename='smpp_full_chains.csv')
    raise Http404("CSV file not found.")


def download_socket_csv(request, filename):
    file_path = os.path.join(SOCKET_CSV_DIR, filename)
    if os.path.exists(file_path):
        return FileResponse(open(file_path,'rb'),
                             as_attachment=True,
                             filename=filename)
    raise Http404("Socket CSV not found.")


def unmatched_view(request, src_ip_port, dst_ip_port, pdu_type):
    filename  = f"chains_{src_ip_port.replace(':','_')}__{dst_ip_port.replace(':','_')}.csv"
    file_path = os.path.join(SOCKET_CSV_DIR, filename)

    results = []
    header  = []
    try:
        with open(file_path, newline='') as f:
            reader = csv.DictReader(f)
            header = reader.fieldnames
            for row in reader:
                if pdu_type == 'submit_resp'    and not row.get('submit_resp_time'):
                    results.append(SimpleNamespace(**row))
                elif pdu_type == 'deliver'      and not row.get('deliver_time'):
                    results.append(SimpleNamespace(**row))
                elif pdu_type == 'deliver_resp' and not row.get('deliver_resp_time'):
                    results.append(SimpleNamespace(**row))
    except FileNotFoundError:
        raise Http404("Socket CSV not found.")

    return render(request, 'unmatched_detail.html', {
        'results': results,
        'header' : header,
        'title'  : f"Unmatched {pdu_type.replace('_',' ').title()} for {src_ip_port} → {dst_ip_port}"
    })


@csrf_exempt
def upload_pcap(request):
    if request.method == 'POST' and request.FILES.get('pcap_file'):
        uploaded_file = request.FILES['pcap_file']
        upload_dir    = os.path.join(settings.BASE_DIR, 'uploaded_pcaps')
        os.makedirs(upload_dir, exist_ok=True)

        file_path = os.path.join(upload_dir, uploaded_file.name)
        with open(file_path, 'wb') as f:
            for chunk in uploaded_file.chunks():
                f.write(chunk)

        script_path = os.path.join(settings.BASE_DIR, 'old.py')
        cmd = ['python3', script_path, upload_dir]
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True
            )
            messages.success(request, f"File uploaded and CSV generated!\n{result.stdout}")
        except subprocess.CalledProcessError as e:
            messages.error(request, f"Error processing file:\n{e.stderr}")

        return HttpResponseRedirect(reverse('search_page'))

    messages.error(request, "No file selected.")
    return HttpResponseRedirect(reverse('search_page'))

@csrf_exempt
def delete_pcaps(request):
    if request.method == "POST":
        upload_dir = os.path.join(settings.BASE_DIR, 'uploaded_pcaps')
        deleted_files = []
        error_files = []

        if os.path.exists(upload_dir):
            for fname in os.listdir(upload_dir):
                fpath = os.path.join(upload_dir, fname)
                if os.path.isfile(fpath):
                    # Check for standard extensions OR the specific dump.pcap pattern
                    if (fname.endswith(".pcap") or 
                        fname.endswith(".pcapng") or 
                        fname.startswith("dump.pcap")):  # Match the new pattern
                        try:
                            os.remove(fpath)
                            deleted_files.append(fname)
                        except Exception as e:
                            error_msg = f"Error deleting {fname}: {e}"
                            messages.error(request, error_msg)
                            error_files.append(fname)

        if deleted_files:
            messages.success(request, f"🗑️ Deleted {len(deleted_files)} PCAP file(s): {', '.join(deleted_files)}")
        else:
            messages.info(request, "No PCAP files found to delete.")

    return HttpResponseRedirect(reverse('search_page'))


