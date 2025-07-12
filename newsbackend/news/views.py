# core/views.py
from rest_framework import generics, status
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.views import APIView
from django.contrib.auth.models import User
from .serializers import UserSerializer
import requests
from django.conf import settings 

class RegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    permission_classes = (AllowAny,) 
    serializer_class = UserSerializer

class NewsAPIView(APIView):
    permission_classes = (IsAuthenticated,) 

    def get(self, request, *args, **kwargs):
        # IMPORTANT: 'q' is mandatory for the 'everything' endpoint
        query = request.query_params.get('q', '').strip() # Get 'q', remove leading/trailing whitespace

        # If 'q' is empty after stripping, return a 400 Bad Request
        if not query:
            return Response(
                {"detail": "The 'q' (query) parameter is required for news searches."},
                status=status.HTTP_400_BAD_REQUEST
            )

        page_size = request.query_params.get('pageSize', 10)
        sort_by = request.query_params.get('sortBy', 'publishedAt') 
        from_date = request.query_params.get('from', '') 

        api_key = settings.NEWS_API_KEY
        
        if not api_key:
            return Response({"detail": "News API Key not configured in settings."}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Base URL for the 'everything' endpoint
        url = "https://newsapi.org/v2/everything"
        
        # Build parameters dictionary
        params = {
            'q': query,
            'sortBy': sort_by,
            'pageSize': page_size,
            'apiKey': api_key,
        }

        if from_date:
            params['from'] = from_date
        
        # Add language if desired (e.g., for English articles)
        params['language'] = 'en' # Explicitly request English articles

        try:
            response = requests.get(url, params=params) # Pass params as a dictionary
            response.raise_for_status() 
            data = response.json()
            
            return Response(data)
        except requests.exceptions.RequestException as e:
            error_detail = "Error fetching news from external API."
            if response.status_code == 400:
                # NewsAPI specific error details from their JSON response
                news_api_error = response.json().get('message', 'Bad Request')
                error_detail = f"News API Error (400): {news_api_error}"
            elif response.status_code == 401:
                error_detail = "News API Error (401): Unauthorized. Check your API key."
            elif response.status_code == 426: # This is a common code for 'upgrade required' by NewsAPI
                 error_detail = "News API Error (426): Upgrade required. You might be using a feature not available on your plan (e.g., older dates, too many results)."
            elif response.status_code == 429:
                error_detail = "News API Error (429): Too Many Requests. You've hit your usage limits."
            elif response.status_code == 500:
                error_detail = "News API Error (500): Server-side issue from NewsAPI.org."
            
            return Response({"detail": error_detail}, status=response.status_code if response.status_code >= 400 else status.HTTP_500_INTERNAL_SERVER_ERROR)
        except Exception as e:
            return Response({"detail": f"An unexpected server error occurred: {e}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)