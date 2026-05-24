import { Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule, NgForm } from '@angular/forms';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { httpResource } from '@angular/common/http';

// Angular Material
import { MatButtonModule } from '@angular/material/button';
import { MatCardModule } from '@angular/material/card';
import { MatChipsModule } from '@angular/material/chips';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatInputModule } from '@angular/material/input';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatSnackBar, MatSnackBarModule } from '@angular/material/snack-bar';
import { MatTableModule } from '@angular/material/table';
import { MatToolbarModule } from '@angular/material/toolbar';
import { MatTooltipModule } from '@angular/material/tooltip';
import { MatTabsModule } from '@angular/material/tabs';
import { MatBadgeModule } from '@angular/material/badge';
import { MatExpansionModule } from '@angular/material/expansion';
import { MatSelectModule } from '@angular/material/select';
import { MatDividerModule } from '@angular/material/divider';

export interface MailUser {
  email: string;
  domain: string;
  active: boolean;
  created_at: string;
}

export interface QuarantineMessage {
  id: number;
  message_id: string;
  sender: string;
  recipient: string;
  subject: string;
  received_at: string;
  score: number;
  verdict: string;
  sa_score: number | null;
  llm_score: number | null;
  auth_score: number | null;
  clamav_clean: boolean | null;
  clamav_virus: string | null;
  adversarial: boolean;
  reasons: string[];
  raw_headers: string | null;
  body_preview: string | null;
  status: string;
  reviewed_by: string | null;
  reviewed_at: string | null;
}

export interface ScoringLogEntry {
  id: number;
  sender: string;
  recipient: string;
  subject: string;
  scored_at: string;
  score: number;
  verdict: string;
  sa_score: number | null;
  llm_score: number | null;
  auth_score: number | null;
  reasons: string[];
  action_taken: string;
}

export interface Stats {
  total: number;
  clean: number;
  spam: number;
  quarantine: number;
  pending_review: number;
  recent: ScoringLogEntry[];
}

@Component({
  selector: 'app-root',
  standalone: true,
  imports: [
    CommonModule,
    FormsModule,
    MatButtonModule,
    MatCardModule,
    MatChipsModule,
    MatFormFieldModule,
    MatIconModule,
    MatInputModule,
    MatProgressBarModule,
    MatSnackBarModule,
    MatTableModule,
    MatToolbarModule,
    MatTooltipModule,
    MatTabsModule,
    MatBadgeModule,
    MatExpansionModule,
    MatSelectModule,
    MatDividerModule,
  ],
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css'],
})
export class AppComponent {
  private http  = inject(HttpClient);
  private snack = inject(MatSnackBar);

  // ---- auth signals ----
  loggedIn  = signal(false);
  loginUser = signal('');
  loginPass = signal('');
  authB64   = signal('');

  // ---- active tab ----
  activeTab = signal(0);

  // ---- httpResource — reactive users list ----
  usersResource = httpResource<MailUser[]>(() =>
    this.loggedIn()
      ? {
          url: '/api/users',
          headers: { Authorization: `Basic ${this.authB64()}` },
        }
      : undefined
  );

  users   = computed(() => this.usersResource.value() ?? []);
  loading = computed(() => this.usersResource.isLoading());

  // ---- quarantine resource ----
  quarantineFilter = signal('');

  quarantineResource = httpResource<QuarantineMessage[]>(() =>
    this.loggedIn()
      ? {
          url: `/api/quarantine?status=${this.quarantineFilter()}`,
          headers: { Authorization: `Basic ${this.authB64()}` },
        }
      : undefined
  );

  quarantine = computed(() => this.quarantineResource.value() ?? []);
  quarantineLoading = computed(() => this.quarantineResource.isLoading());

  // ---- stats resource ----
  statsResource = httpResource<Stats>(() =>
    this.loggedIn()
      ? {
          url: '/api/stats',
          headers: { Authorization: `Basic ${this.authB64()}` },
        }
      : undefined
  );

  stats = computed(() => this.statsResource.value() ?? {
    total: 0, clean: 0, spam: 0, quarantine: 0, pending_review: 0, recent: []
  } as Stats);

  // ---- table columns ----
  readonly userColumns = ['email', 'domain', 'active', 'created_at', 'actions'];
  readonly qColumns = ['score', 'verdict', 'sender', 'subject', 'received_at', 'actions'];
  readonly logColumns = ['score', 'verdict', 'sender', 'subject', 'scored_at', 'action_taken'];

  // ---- new-user form ----
  newEmail    = signal('');
  newPassword = signal('');

  // ---- inline password edit ----
  editEmail = signal('');
  editPw    = signal('');

  // ---- expanded quarantine detail ----
  expandedQId = signal<number | null>(null);

  // ---- expanded scoring log detail ----
  expandedLogId = signal<number | null>(null);

  toggleLog(id: number) {
    this.expandedLogId.set(this.expandedLogId() === id ? null : id);
  }

  // ---- private helpers ----
  private get headers() {
    return new HttpHeaders({ Authorization: `Basic ${this.authB64()}` });
  }

  private notify(msg: string, ok = true) {
    this.snack.open(msg, 'OK', {
      duration: 3500,
      panelClass: ok ? [] : ['snack-err'],
    });
  }

  // ---- login ----
  login() {
    const b64 = btoa(`${this.loginUser()}:${this.loginPass()}`);
    this.http
      .get<MailUser[]>('/api/users', {
        headers: new HttpHeaders({ Authorization: `Basic ${b64}` }),
      })
      .subscribe({
        next: () => {
          this.authB64.set(b64);
          this.loggedIn.set(true);
        },
        error: () =>
          this.notify('Credentiale invalide sau server indisponibil.', false),
      });
  }

  logout() {
    this.loggedIn.set(false);
    this.authB64.set('');
    this.loginUser.set('');
    this.loginPass.set('');
  }

  // ---- user CRUD ----
  createUser(form: NgForm) {
    this.http
      .post(
        '/api/users',
        { email: this.newEmail(), password: this.newPassword() },
        { headers: this.headers }
      )
      .subscribe({
        next: () => {
          this.notify(`Cont ${this.newEmail()} creat.`);
          this.newEmail.set('');
          this.newPassword.set('');
          form.resetForm();
          this.usersResource.reload();
        },
        error: (e: { error?: { error?: string } }) =>
          this.notify(e.error?.error ?? 'Eroare la creare.', false),
      });
  }

  confirmDelete(email: string) {
    if (!confirm(`Stergi contul ${email}?`)) return;
    this.http
      .delete(`/api/users/${encodeURIComponent(email)}`, {
        headers: this.headers,
      })
      .subscribe({
        next: () => {
          this.notify(`${email} sters.`);
          this.usersResource.reload();
        },
        error: (e: { error?: { error?: string } }) =>
          this.notify(e.error?.error ?? 'Eroare la stergere.', false),
      });
  }

  startEdit(email: string) {
    this.editEmail.set(email);
    this.editPw.set('');
  }

  cancelEdit() {
    this.editEmail.set('');
  }

  savePassword() {
    this.http
      .put(
        `/api/users/${encodeURIComponent(this.editEmail())}/password`,
        { password: this.editPw() },
        { headers: this.headers }
      )
      .subscribe({
        next: () => {
          this.notify('Parola schimbata.');
          this.cancelEdit();
        },
        error: (e: { error?: { error?: string } }) =>
          this.notify(e.error?.error ?? 'Eroare.', false),
      });
  }

  // ---- quarantine actions ----
  releaseMessage(id: number) {
    this.http
      .post(`/api/quarantine/${id}/release`, {}, { headers: this.headers })
      .subscribe({
        next: () => {
          this.notify('Mesaj eliberat din carantina.');
          this.quarantineResource.reload();
          this.statsResource.reload();
        },
        error: () => this.notify('Eroare la eliberare.', false),
      });
  }

  deleteMessage(id: number) {
    if (!confirm('Stergi definitiv acest mesaj?')) return;
    this.http
      .post(`/api/quarantine/${id}/delete`, {}, { headers: this.headers })
      .subscribe({
        next: () => {
          this.notify('Mesaj sters.');
          this.quarantineResource.reload();
          this.statsResource.reload();
        },
        error: () => this.notify('Eroare la stergere.', false),
      });
  }

  toggleDetail(id: number) {
    this.expandedQId.set(this.expandedQId() === id ? null : id);
  }

  // ---- helpers ----
  scoreColor(score: number): string {
    if (score >= 0.6) return 'warn';
    if (score >= 0.3) return 'accent';
    return 'primary';
  }

  verdictIcon(verdict: string): string {
    switch (verdict) {
      case 'SPAM': return 'dangerous';
      case 'QUARANTINE': return 'warning';
      default: return 'check_circle';
    }
  }

  formatScore(score: number | null): string {
    return score !== null ? score.toFixed(2) : 'N/A';
  }

  refreshAll() {
    this.usersResource.reload();
    this.quarantineResource.reload();
    this.statsResource.reload();
  }
}
