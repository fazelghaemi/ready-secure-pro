(function ($) {
    'use strict';

    $(document).ready(function () {

        // --- Tab Navigation Logic ---
        function switchTab(tabId) {
            $('.rsp-nav-item').removeClass('active');
            $('.rsp-panel').removeClass('show');

            const currentTab = $('.rsp-nav-item[data-tab="' + tabId + '"]');
            currentTab.addClass('active');
            $('#tab-' + tabId).addClass('show');
            
            // Store the active tab in localStorage
            localStorage.setItem('rsp_active_tab', tabId);
        }

        $('.rsp-nav-item').on('click', function (e) {
            e.preventDefault();
            const tabId = $(this).data('tab');
            switchTab(tabId);
        });

        // Restore the last active tab on page load
        const lastTab = localStorage.getItem('rsp_active_tab');
        if (lastTab) {
            switchTab(lastTab);
        } else {
            switchTab('overview'); // Default tab
        }


        // --- AJAX Actions ---
        function runScan(button, output, action, nonce) {
            const originalText = $(button).text();
            $(button).prop('disabled', true).text('Scanning...');
            $(output).text('Starting scan...');

            $.post(RSP_DATA.ajax_url, { action: action, _ajax_nonce: nonce })
                .done(function (res) {
                    if (res.success) {
                        if (typeof res.data === 'string' || res.data.report) {
                             $(output).text(res.data.report || res.data);
                        } else {
                             $(output).text(JSON.stringify(res.data, null, 2));
                        }
                    } else {
                        $(output).text('Error: ' + (res.data.message || 'Unknown error occurred.'));
                    }
                })
                .fail(function () {
                    $(output).text('An unexpected error occurred during the AJAX request.');
                })
                .always(function () {
                    $(button).prop('disabled', false).text(originalText);
                });
        }
        
        // Malware Scan
        $('#rsp-run-malware-scan').on('click', function () {
            runScan(this, '#rsp-malware-out', 'rsp_run_malware_scan', RSP_DATA.nonce);
        });

        // Integrity Scan
        $('#rsp-run-integrity').on('click', function () {
            runScan(this, '#rsp-integrity-out', 'rsp_scan_integrity', RSP_DATA.nonce);
        });
        
        // FS Permissions Scan
        $('#rsp-scan-fs').on('click', function () {
            runScan(this, '#rsp-fs-out', 'rsp_scan_fs', RSP_DATA.nonce);
        });
        
        // --- Logs ---
        function fetchLogs() {
            $('#rsp-log-out').text('Loading...');
            $.post(RSP_DATA.ajax_url, { action: 'rsp_get_logs', _ajax_nonce: RSP_DATA.nonce }, function (res) {
                if(res.success && res.data.length > 0) {
                     $('#rsp-log-out').text(JSON.stringify(res.data, null, 2));
                } else {
                     $('#rsp-log-out').text('No log entries found.');
                }
            });
        }
        
        if($('#tab-logs').length) {
            fetchLogs();
        }

        // --- Settings Import/Export ---
        $('#rsp-export-settings').on('click', function () {
            $.post(RSP_DATA.ajax_url, { action: 'rsp_export_settings', _ajax_nonce: RSP_DATA.nonce }, function (res) {
                $('#rsp-settings-json').val(JSON.stringify(res.data || {}, null, 2));
                $('#rsp-settings-hint').text('Settings exported. You can copy the JSON above.');
            });
        });

        $('#rsp-import-settings').on('click', function () {
            const payload = $('#rsp-settings-json').val();
            if (!payload) {
                 $('#rsp-settings-hint').text('Error: Text area is empty.');
                 return;
            }
            $.post(RSP_DATA.ajax_url, { action: 'rsp_import_settings', _ajax_nonce: RSP_DATA.nonce, payload: payload }, function (res) {
                $('#rsp-settings-hint').text(res.success ? 'Settings imported successfully. Page will reload.' : ('Error: ' + res.data));
                if (res.success) {
                    setTimeout(() => window.location.reload(), 1500);
                }
            });
        });
    });

})(jQuery);