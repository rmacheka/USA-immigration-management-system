import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import statsmodels.api as sm
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("analytics")

class ImmigrationAnalytics:
    """Class to perform advanced analytics on immigration data"""
    
    @staticmethod
    def predict_permit_expirations(df, forecast_days=180):
        """
        Predict number of permit expirations over the next period
        
        Args:
            df (DataFrame): DataFrame containing immigration records
            forecast_days (int): Number of days to forecast
        
        Returns:
            DataFrame: DataFrame with forecasted expirations by date
        """
        try:
            # Convert permit expiry to datetime
            df_copy = df.copy()
            df_copy['Permit Expiry'] = pd.to_datetime(df_copy['Permit Expiry'], errors='coerce')
            
            # Drop rows with invalid date
            df_copy = df_copy.dropna(subset=['Permit Expiry'])
            
            if len(df_copy) == 0:
                return pd.DataFrame(columns=['Date', 'Expirations'])
            
            # Count expirations by date
            expiry_counts = df_copy['Permit Expiry'].dt.date.value_counts().sort_index()
            expiry_counts = expiry_counts.reset_index()
            expiry_counts.columns = ['Date', 'Expirations']
            
            # Ensure daily data with 0s for days with no expirations
            date_range = pd.date_range(
                start=expiry_counts['Date'].min(),
                end=expiry_counts['Date'].max(),
                freq='D'
            )
            
            full_range = pd.DataFrame({'Date': date_range})
            expiry_counts = pd.merge(full_range, expiry_counts, on='Date', how='left')
            expiry_counts['Expirations'] = expiry_counts['Expirations'].fillna(0)
            
            # Create time series model
            expiry_ts = expiry_counts.set_index('Date')['Expirations']
            
            # Use ARIMA model for forecasting
            model = sm.tsa.ARIMA(expiry_ts, order=(1, 1, 1))
            model_fit = model.fit()
            
            # Create future dates for prediction
            last_date = expiry_counts['Date'].max()
            future_dates = pd.date_range(
                start=last_date + timedelta(days=1),
                periods=forecast_days,
                freq='D'
            )
            
            # Generate predictions
            forecast = model_fit.predict(
                start=len(expiry_ts),
                end=len(expiry_ts) + forecast_days - 1
            )
            
            # Combine with future dates
            forecast_df = pd.DataFrame({
                'Date': future_dates,
                'Forecasted_Expirations': forecast.values
            })
            
            # Ensure non-negative values
            forecast_df['Forecasted_Expirations'] = forecast_df['Forecasted_Expirations'].clip(lower=0)
            forecast_df['Forecasted_Expirations'] = forecast_df['Forecasted_Expirations'].round().astype(int)
            
            return forecast_df
            
        except Exception as e:
            logger.error(f"Error in prediction: {e}")
            return pd.DataFrame(columns=['Date', 'Forecasted_Expirations'])
    
    @staticmethod
    def identify_immigrant_clusters(df):
        """
        Identify clusters of immigrants based on their characteristics
        
        Args:
            df (DataFrame): DataFrame containing immigration records
        
        Returns:
            tuple: (DataFrame with cluster assignments, cluster center information)
        """
        try:
            df_copy = df.copy()
            
            # Select features for clustering
            features = []
            
            # Convert status to numerical values
            if 'Status' in df_copy.columns:
                status_map = {
                    'Permanent': 3,
                    'Temporary': 2,
                    'Expired': 1,
                    'Illegal': 0
                }
                df_copy['Status_Code'] = df_copy['Status'].map(status_map)
                features.append('Status_Code')
            
            # Convert permit expiry to days from now
            if 'Permit Expiry' in df_copy.columns:
                df_copy['Permit Expiry'] = pd.to_datetime(df_copy['Permit Expiry'], errors='coerce')
                today = datetime.now().date()
                df_copy['Days_To_Expiry'] = (df_copy['Permit Expiry'].dt.date - today).dt.days
                df_copy['Days_To_Expiry'] = df_copy['Days_To_Expiry'].fillna(-365)  # Default for missing
                features.append('Days_To_Expiry')
            
            # If no suitable features, return empty result
            if not features:
                return df_copy, pd.DataFrame()
            
            # Select rows with all features
            data_for_clustering = df_copy[features].dropna()
            
            if len(data_for_clustering) < 5:  # Not enough data for meaningful clustering
                return df_copy, pd.DataFrame()
            
            # Scale the features
            scaler = StandardScaler()
            scaled_data = scaler.fit_transform(data_for_clustering)
            
            # Determine optimal number of clusters (2-5)
            inertia = []
            for k in range(2, min(6, len(data_for_clustering) + 1)):
                kmeans = KMeans(n_clusters=k, random_state=42)
                kmeans.fit(scaled_data)
                inertia.append(kmeans.inertia_)
            
            # Find optimal k using elbow method (simplified)
            optimal_k = 2
            for i in range(1, len(inertia)):
                if inertia[i-1] - inertia[i] < inertia[0] * 0.2:
                    optimal_k = i + 1
                    break
            
            # Apply KMeans with optimal K
            kmeans = KMeans(n_clusters=optimal_k, random_state=42)
            cluster_labels = kmeans.fit_predict(scaled_data)
            
            # Add cluster labels to original data rows that were used
            df_copy.loc[data_for_clustering.index, 'Cluster'] = cluster_labels
            
            # Get cluster centers and convert back to original scale
            centers = scaler.inverse_transform(kmeans.cluster_centers_)
            
            # Create cluster center information
            cluster_info = pd.DataFrame(centers, columns=features)
            cluster_info['Cluster'] = range(optimal_k)
            cluster_info['Count'] = np.bincount(cluster_labels)
            
            # Add interpretation
            if 'Status_Code' in cluster_info.columns:
                # Convert status code back to text for readability
                inv_status_map = {v: k for k, v in status_map.items()}
                cluster_info['Dominant_Status'] = cluster_info['Status_Code'].round().map(inv_status_map)
            
            if 'Days_To_Expiry' in cluster_info.columns:
                # Add expiry interpretation
                def interpret_expiry(days):
                    if days < 0:
                        return "Expired"
                    elif days < 30:
                        return "Expiring soon"
                    elif days < 180:
                        return "Medium-term"
                    else:
                        return "Long-term"
                
                cluster_info['Expiry_Category'] = cluster_info['Days_To_Expiry'].apply(interpret_expiry)
            
            return df_copy, cluster_info
            
        except Exception as e:
            logger.error(f"Error in clustering: {e}")
            return df, pd.DataFrame()
    
    @staticmethod
    def analyze_transition_patterns(df_current, df_previous=None):
        """
        Analyze how immigrant statuses have changed over time
        
        Args:
            df_current (DataFrame): Current DataFrame containing immigration records
            df_previous (DataFrame, optional): Previous DataFrame for comparison
        
        Returns:
            dict: Dictionary with transition analysis
        """
        try:
            if df_previous is None or 'Status' not in df_current.columns or 'Status' not in df_previous.columns:
                # Can't analyze transitions without previous data or status column
                current_status_counts = df_current['Status'].value_counts().to_dict() if 'Status' in df_current.columns else {}
                return {
                    'current_distribution': current_status_counts,
                    'transitions': {},
                    'notable_changes': []
                }
            
            # Ensure both DataFrames have USCIS Number column for matching
            if 'USCIS Number' not in df_current.columns or 'USCIS Number' not in df_previous.columns:
                return {
                    'error': 'Missing USCIS Number column for matching records'
                }
            
            # Create dictionaries mapping USCIS numbers to statuses
            current_statuses = dict(zip(df_current['USCIS Number'], df_current['Status']))
            previous_statuses = dict(zip(df_previous['USCIS Number'], df_previous['Status']))
            
            # Find common USCIS numbers
            common_uscis = set(current_statuses.keys()) & set(previous_statuses.keys())
            
            # Track transitions
            transitions = {}
            for uscis in common_uscis:
                prev_status = previous_statuses[uscis]
                curr_status = current_statuses[uscis]
                
                if prev_status != curr_status:
                    transition_key = f"{prev_status} -> {curr_status}"
                    if transition_key not in transitions:
                        transitions[transition_key] = 0
                    transitions[transition_key] += 1
            
            # Calculate current distribution
            current_status_counts = df_current['Status'].value_counts().to_dict()
            previous_status_counts = df_previous['Status'].value_counts().to_dict()
            
            # Identify notable changes (>10% change)
            notable_changes = []
            for status in set(current_status_counts.keys()) | set(previous_status_counts.keys()):
                curr_count = current_status_counts.get(status, 0)
                prev_count = previous_status_counts.get(status, 0)
                
                if prev_count > 0:
                    percent_change = (curr_count - prev_count) / prev_count * 100
                    if abs(percent_change) >= 10:
                        notable_changes.append({
                            'status': status,
                            'previous_count': prev_count,
                            'current_count': curr_count,
                            'percent_change': round(percent_change, 1)
                        })
            
            # Sort notable changes by absolute percent change
            notable_changes.sort(key=lambda x: abs(x['percent_change']), reverse=True)
            
            return {
                'current_distribution': current_status_counts,
                'previous_distribution': previous_status_counts,
                'transitions': transitions,
                'notable_changes': notable_changes
            }
            
        except Exception as e:
            logger.error(f"Error in transition analysis: {e}")
            return {'error': str(e)}
    
    @staticmethod
    def nationality_trend_analysis(df):
        """
        Analyze trends in nationalities over time
        
        Args:
            df (DataFrame): DataFrame containing immigration records
        
        Returns:
            DataFrame: Analysis of nationality trends
        """
        try:
            if 'Nationality' not in df.columns or 'Permit Expiry' not in df.columns:
                return pd.DataFrame()
            
            # Convert permit expiry to datetime
            df_copy = df.copy()
            df_copy['Permit Expiry'] = pd.to_datetime(df_copy['Permit Expiry'], errors='coerce')
            
            # Drop rows with invalid date
            df_copy = df_copy.dropna(subset=['Permit Expiry', 'Nationality'])
            
            if len(df_copy) == 0:
                return pd.DataFrame()
            
            # Bin dates into quarters
            df_copy['Quarter'] = df_copy['Permit Expiry'].dt.to_period('Q')
            
            # Count by nationality and quarter
            nationality_counts = df_copy.groupby(['Quarter', 'Nationality']).size().unstack(fill_value=0)
            
            # Calculate quarterly growth rates
            growth_rates = nationality_counts.pct_change()
            
            # Calculate average growth rate per nationality
            avg_growth = growth_rates.mean()
            
            # Get current count per nationality
            current_counts = df_copy['Nationality'].value_counts()
            
            # Combine into a summary DataFrame
            result = pd.DataFrame({
                'Current_Count': current_counts,
                'Avg_Quarterly_Growth': avg_growth
            })
            
            # Clean up and sort
            result = result.fillna(0)
            result['Avg_Quarterly_Growth'] = result['Avg_Quarterly_Growth'] * 100  # Convert to percentage
            result = result.sort_values('Current_Count', ascending=False)
            
            # Classify trend
            def classify_trend(row):
                if row['Avg_Quarterly_Growth'] > 5:
                    return "Strong growth"
                elif row['Avg_Quarterly_Growth'] > 0:
                    return "Moderate growth"
                elif row['Avg_Quarterly_Growth'] > -5:
                    return "Stable"
                else:
                    return "Declining"
            
            result['Trend'] = result.apply(classify_trend, axis=1)
            
            return result
            
        except Exception as e:
            logger.error(f"Error in nationality trend analysis: {e}")
            return pd.DataFrame()

# Create convenience functions
def predict_expirations(df, days=180):
    """Convenience function for permit expiration prediction"""
    return ImmigrationAnalytics.predict_permit_expirations(df, forecast_days=days)

def cluster_immigrants(df):
    """Convenience function for immigrant clustering"""
    return ImmigrationAnalytics.identify_immigrant_clusters(df)

def analyze_status_transitions(current_df, previous_df=None):
    """Convenience function for transition analysis"""
    return ImmigrationAnalytics.analyze_transition_patterns(current_df, previous_df)

def analyze_nationality_trends(df):
    """Convenience function for nationality trend analysis"""
    return ImmigrationAnalytics.nationality_trend_analysis(df) 