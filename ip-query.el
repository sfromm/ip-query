;;; ip-query.el --- IP query tool
;; Copyright (C) 2021 by Stephen Fromm

;; Author: Stephen Fromm
;; URL: https://github.com/sfromm/ip-query
;; Package-Requires: ((emacs "24.1"))
;; Keywords: network ip
;; Version: 0.1

;; This program is not part of GNU Emacs
;;
;; This file is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation; either version 2, or (at your option)
;; any later version.
;;
;; This file is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.
;;
;; You should have received a copy of the GNU General Public License along
;; with this program; if not, write to the Free Software Foundation, Inc.,
;; 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
;;
;;; Commentary:
;;
;;; Code:

(require 'dns)

(defconst ip-query-ipv4-length 32 "Max IPv4 length.")

(defconst ip-query-ipv6-length 128 "Max IPv6 length.")

(defconst ip-query-keywords-regex
  (concat
   "^"
   (regexp-opt
    '("Address" "Netmask" "Wildcard"
      "HostMin" "HostMax" "Network"
      "Broadcast" "Hosts/Net") 'words))
  "Regular expressions for IP Query.")

(defcustom ip-query-font-lock-keywords
  (list
   (list ip-query-keywords-regex 0 font-lock-keyword-face))
  "Default expressions to highlight in ipquery mode."
  :type 'sexp
  :group 'net-utils)


;;
;; Mode
;;

(defvar ip-query-buffer-name "*ip-query*" "Name of buffer to run IP query.")

(defvar ipquery-mode-map
  (let ((map (make-sparse-keymap)))
    (suppress-keymap map)
    (define-key map "q" 'ip-query-exit)
    map))

(define-derived-mode ip-query-mode fundamental-mode "IP-Query"
  "Major mode for displaying IP output."
  (buffer-disable-undo)
  (set (make-local-variable 'font-lock-defaults) '(ip-query-font-lock-keywords))
  (when (featurep 'font-lock)
    (font-lock-set-defaults)))

(defun ip-query-exit ()
  "Bury ip-query output buffer."
  (interactive)
  (quit-window (current-buffer)))

(defun ip-query-get-buffer ()
  "Get the ip-query buffer."
  (let ((buffer (get-buffer-create ip-query-buffer-name)))
    (with-current-buffer buffer
      (ip-query-mode))
    buffer))

(defun ip-query-last ()
  "Go to end of ipquery buffer."
  (interactive)
  (goto-char (point-max)))


;;
;; Functions
;;

(defun ip-query--dns-cymru-txt-query (name)
  "Look up a TXT RR NAME from Cymru and return the split result."
  (let* ((answer (dns-query name 'TXT)))
    (when answer
      (split-string answer "|" t " *"))))

(defun ip-query--dns-soa (name)
  "Look up SOA RR for NAME."
  (let* ((result (dns-query name 'SOA t nil))
         (rr nil)
         (answer nil))
    (when (assoc 'answers result)
      (setq answer (cadr (assoc 'data (nth 0 (cadr (assoc 'answers result)))))))
    answer))

(defun ip-query--reverse-ip (ip)
  "Return IP in reversed format, typically for doing DNS PTR lookups."
  (mapconcat 'identity (nreverse (split-string ip "\\.")) "."))

(defun ip-query-asn (asn)
  "Query for an Autonomous System ASN."
  (interactive "sASN: ")
  (let* ((result (ip-query--dns-cymru-txt-query (concat "AS" asn ".asn.cymru.com")))
         (answer nil))
    (when result
      (setq answer (list (list 'asn (nth 0 result))
                         (list 'country (nth 1 result))
                         (list 'rir (nth 2 result))
                         (list 'name (nth 4 result))))
      (when (called-interactively-p 'interactive)
        (message "%s" answer)))
    answer))

(defun ip-query-asn-origin (ip)
  "Query for IP origin ASN."
  (interactive "sIP: ")
  (let* ((reverse (reverse-ip ip))
         (result (ip-query--dns-cymru-txt-query (concat reverse ".origin.asn.cymru.com")))
         (answer))
    (message "%s" answer)
    (setq answer (list (list 'asn (nth 0 result))
                       (list 'prefix (nth 1 result))
                       (list 'country (nth 2 result))
                       (list 'rir (nth 3 result))))
    (when (called-interactively-p 'interactive)
      (message "%s" answer))
    answer))

(defun ip-query-dns-ptr (ip)
  "Return DNS PTR information on IP.
This will return the ip, the PTR RR, and the query itself.
The authority zone will be included if present in the DNS response."
  (interactive "sIP: ")
  (require 'dns)
  (let ((result (dns-query ip 'PTR t t))
        (answer '())
        (rr)
        (rrtype))
    (setq answer (list (list 'ip ip)))
    (setq answer (append
                  (list
                   ;; long-winded way to get the PTR query
                   (list 'query (car (car (cadr (assoc 'queries result))))))
                  answer))
    (when (assoc 'answers result)
      (dolist (arg2 (cadr (assoc 'answers result)))
        (when (cdr (assoc 'type arg2)) ;; make sure RR type is not nil
          (setq rrtype (cadr (assoc 'type arg2)))
          (setq rr (list (list rrtype (cadr (assoc 'data arg2)))))
          (setq answer (append rr answer)))))
    ;; pull in authority information from SOA
    (when (assoc 'authorities result)
      (when (car (nth 0 (cadr (assoc 'authorities result))))
        (setq answer (append (list (list 'authority (car (nth 0 (cadr (assoc 'authorities result)))))) answer))))
    (when (called-interactively-p 'interactive)
      (message "%s" answer))
    answer))


;;
;; main entry point
;;

(defun ip-query (ip)
  "Query information on an IP.
Will return available DNS, BGP origin, and associated ASN information."
  (interactive "sIP: ")
  (let* ((answer '())
         (dns (ip-query-dns-ptr ip))
         (origin (ip-query-asn-origin ip))
         (asn (ip-query-asn (cadr (assoc 'asn origin)))))
    (setq answer (list (list 'dns dns)
                       (list 'origin origin)
                       (list 'asn asn)))
    (when (called-interactively-p 'interactive)
      (message "%s" answer))
    answer))

;;; ip-query.el ends here
