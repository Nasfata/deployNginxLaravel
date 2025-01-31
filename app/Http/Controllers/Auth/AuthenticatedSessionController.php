<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Http\Requests\Auth\LoginRequest;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\View\View;

class AuthenticatedSessionController extends Controller
{
    /**
     * Display the login view.
     */
    public function create(): View
    {
        return view('auth.login');
    }

    /**
     * Handle an incoming authentication request.
     */
    public function store(Request $request): RedirectResponse
    {
        // Validation des données entrées par l'utilisateur
        $request->validate([
            'login' => ['required', 'string'], // Peut être email ou téléphone
            'password' => ['required', 'string'],
        ]);

        // Déterminer si l'utilisateur a entré un email ou un téléphone
        $loginField = filter_var($request->login, FILTER_VALIDATE_EMAIL) ? 'email' : 'telephone';

        // Tentative d'authentification avec le champ approprié
        if (Auth::attempt([$loginField => $request->login, 'password' => $request->password])) {
            $request->session()->regenerate();

            return redirect()->intended(route('dashboard', absolute: false));
        }

        // Si l'authentification échoue, retour avec une erreur
        return back()->withErrors([
            'login' => 'Les informations de connexion sont incorrectes.',
        ]);
    }

    /**
     * Destroy an authenticated session.
     */
    public function destroy(Request $request): RedirectResponse
    {
        Auth::guard('web')->logout();

        $request->session()->invalidate();

        $request->session()->regenerateToken();

        return redirect('/');
    }
}
