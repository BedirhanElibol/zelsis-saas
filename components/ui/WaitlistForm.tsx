'use client';

import { useState } from 'react';
import { Button } from './button';
import { Input } from './input';
import { toast } from 'sonner';
import { Loader2 } from 'lucide-react';

export function WaitlistForm({ source = 'direct', framework = '' }: { source?: string, framework?: string }) {
  const [email, setEmail] = useState('');
  const [loading, setLoading] = useState(false);
  const [submitted, setSubmitted] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email) return;

    setLoading(true);
    try {
      const res = await fetch('/api/v1/waitlist', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email, source, framework_interest: framework }),
      });

      if (!res.ok) {
        throw new Error('Failed to join waitlist');
      }

      setSubmitted(true);
      toast.success('Successfully joined the waitlist!');
    } catch (error) {
      toast.error('Something went wrong. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  if (submitted) {
    return (
      <div className="p-4 rounded-md bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-center">
        Thank you for joining! We'll be in touch soon.
      </div>
    );
  }

  return (
    <form onSubmit={handleSubmit} className="flex w-full max-w-sm items-center space-x-2">
      <Input
        type="email"
        placeholder="Enter your email"
        value={email}
        onChange={(e: React.ChangeEvent<HTMLInputElement>) => setEmail(e.target.value)}
        required
        disabled={loading}
        className="bg-[#141414] border-white/10 text-white"
      />
      <Button type="submit" disabled={loading} className="bg-white text-black hover:bg-gray-200">
        {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Get Early Access'}
      </Button>
    </form>
  );
}
