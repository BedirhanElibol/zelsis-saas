import type { RuleCase } from '../cases';
import type { CodeFile } from '../../../lib/scanner-engine';

const f = (path: string, content: string): CodeFile[] => [{ path, content }];

export const CASES: RuleCase[] = [
  {
    ruleIds: [28823],
    name: 'GAP-23 setattr loop over request.data/request.json vs DRF validated_data, form.cleaned_data, and Pydantic model_dump(exclude_unset=True)',
    detects: [
      ...f('app/views.py', `def update_profile(request, user):
    for k, v in request.data.items():
        setattr(user, k, v)
    user.save()
`),
      ...f('app/routes/users.py', `async def patch_user(request, user):
    updates = await request.json()
    for key, value in updates.items():
        setattr(user, key, value)
`)
    ],
    ignores: [
      ...f('app/serializers.py', `class UserSerializer:
    def update(self, instance, validated_data):
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        return instance
`),
      ...f('app/views_drf.py', `def save_serializer(serializer, form, instance):
    for attr, value in serializer.validated_data.items():
        setattr(instance, attr, value)
    for field, val in form.cleaned_data.items():
        setattr(instance, field, val)
`),
      ...f('app/api/items.py', `def update_item(payload, item):
    update_data = payload.model_dump(exclude_unset=True)
    for k, v in update_data.items():
        setattr(item, k, v)
    for k, v in payload.dict(exclude_unset=True).items():
        setattr(item, k, v)
`)
    ]
  }
];
