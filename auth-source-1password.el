;;; auth-source-1password.el --- 1password integration for auth-source -*- lexical-binding: t; -*-

;; Copyright (C) 2023 Dominick LoBraico
;; SPDX-License-Identifier: GPL-3.0-or-later

;; Author: Dominick LoBraico <auth-source-1password@lobrai.co>
;; Created: 2023-04-09
;; URL: https://github.com/dlobraico

;; Package-Requires: ((emacs "24.4"))

;; Version: 0.0.1

;;; Commentary:
;; This package adds 1password support to auth-source by calling the op CLI.
;; Heavily inspired by the auth-source-gopass package
;; (https://github.com/triplem/auth-source-gopass)

;;; Code:
(require 'auth-source)

(defgroup auth-source-1password nil
  "1password auth source settings."
  :group 'auth-source
  :tag "auth-source-1password"
  :prefix "1password-")

(defcustom auth-source-1password-vault "Personal"
  "1Password vault to use when searching for secrets."
  :type 'string
  :group 'auth-source-1password)

(defcustom auth-source-1password-executable "op"
  "Executable used for 1password."
  :type 'string
  :group 'auth-source-1password)

(defcustom auth-source-1password-construct-secret-reference 'auth-source-1password--1password-construct-entry-path
  "Function to construct the query path in the 1password store."
  :type 'function
  :group 'auth-source-1password)

(defun auth-source-1password--1password-construct-entry-path (_backend _type host user _port)
  "Construct the full entry-path for the 1password entry for HOST and USER.
Usually starting with the `auth-source-1password-vault', followed
by host and user."
  (mapconcat #'identity (list auth-source-1password-vault host user) "/"))

(cl-defun auth-source-1password-search (&rest spec
                                           &key backend type host user port
                                           &allow-other-keys)
  "Search 1password for the specified user and host.
SPEC, BACKEND, TYPE, HOST, USER and PORT are required by auth-source.

Return a list holding a single (:user USER :secret SECRET) plist when the
reference resolves, or nil when the `op' executable is missing, the reference
is empty, the lookup fails, or no secret is returned.  Returning nil for an
unresolved reference lets auth-source fall through to the remaining backends
instead of handing the caller `op's error output as a bogus secret.  On
failure `op's output is reported through `auth-source-do-debug', so it is
visible when `auth-source-debug' is enabled and silent otherwise."
  (let ((executable (executable-find auth-source-1password-executable))
        (reference (funcall auth-source-1password-construct-secret-reference
                            backend type host user port)))
    (cond
     ((not executable)
      ;; If no executable was found, return nil and show a warning.
      (warn "`auth-source-1password': Could not find executable '%s' to query 1password"
            auth-source-1password-executable))
     ;; A custom `auth-source-1password-construct-secret-reference' may return
     ;; nil (or "") to opt out of this query; skip the `op' call and let other
     ;; backends answer.
     ((or (null reference) (string= reference "")) nil)
     (t
      (let (output status)
        (with-temp-buffer
          ;; `call-process' (unlike `shell-command-to-string') hands back the
          ;; exit status, so we can tell a resolved reference from an `op'
          ;; error.  stdout and stderr are mixed into this buffer: on success
          ;; it holds the secret, on failure `op's diagnostics.
          (setq status (call-process executable nil t nil
                                     "read" (concat "op://" reference))
                output (string-trim (buffer-string))))
        (if (and (eq status 0) (not (string= output "")))
            (list (list :user user :secret output))
          ;; Surface the failure only through auth-source's own debug channel
          ;; so a routine miss (e.g. a host kept elsewhere) stays quiet.
          (auth-source-do-debug
           "auth-source-1password: `op read op://%s' failed (status %s): %s"
           reference status output)
          nil))))))

;;;###autoload
(defun auth-source-1password-enable ()
  "Enable the 1password auth source."
  (add-to-list 'auth-sources '1password)
  (auth-source-forget-all-cached))

(defvar auth-source-1password-backend
  (auth-source-backend
   :source "."
   :type 'password-store
   :search-function #'auth-source-1password-search))

(defun auth-source-1password-backend-parse (entry)
  "Create a 1password auth-source backend from ENTRY."
  (when (eq entry '1password)
    (auth-source-backend-parse-parameters entry auth-source-1password-backend)))

(if (boundp 'auth-source-backend-parser-functions)
    (add-hook 'auth-source-backend-parser-functions #'auth-source-1password-backend-parse)
  (advice-add 'auth-source-backend-parse :before-until #'auth-source-1password-backend-parse))

(provide 'auth-source-1password)
;;; auth-source-1password.el ends here
